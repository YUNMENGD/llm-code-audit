"""知识库检索（RAG）：向量语义 + 关键词打分 融合。

- 有关键词命中但语义不显的词，靠向量补召回；向量漂移的误召，靠关键词加权稳住。
- 无 API Key / 无 numpy 时，自动降级为纯关键词打分（行为与 v0.1 一致，离线测试可跑）。
- retrieve() 签名恒定，audit 模块对底层实现无感知（对应 ICD §3）。
- 知识条目向量本地缓存于 data/vec/（派生物，删了可重建，不入库）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge" / "defects"
DATA_VEC = Path(__file__).resolve().parent.parent / "data" / "vec"

# 并发审计时，知识库向量矩阵只允许一个线程构建，其余等待复用
_KB_LOCK = threading.Lock()

_STOP = {"the", "and", "for", "with", "that", "this", "def", "return", "class",
         "import", "from", "self", "none", "true", "false", "if", "else", "try"}


def load_knowledge() -> list[dict]:
    items: list[dict] = []
    if not KNOWLEDGE_DIR.exists():
        return items
    for f in sorted(KNOWLEDGE_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        items.extend(data.get("items", []))
    return items


def _kw_score(query_lower: str, qwords: set, it: dict) -> float:
    s = 0.0
    for t in it.get("triggers", []):
        if t.lower() in query_lower:
            s += 3
    for tag in it.get("tags", []):
        if tag.lower() in qwords:
            s += 2
    for w in re.findall(r"[a-z_]{3,}", it.get("title", "").lower()):
        if w in qwords:
            s += 1
    return s


def _embed_text(it: dict) -> str:
    text = " ".join([
        it.get("title", ""), it.get("pattern", ""),
        " ".join(it.get("tags", [])), " ".join(it.get("triggers", [])),
    ])
    return text[:1500]                    # 截断：避免超长输入拖垮整批向量化


def _kb_query_vector(query: str) -> str:
    """查询侧截断：检索质量主要取决于开头的代码特征，长尾截掉省 token。"""
    return query[:1200]


# 知识向量内存缓存：{"hash","ids","mat"}（mat 为按行 L2 归一化的 numpy 矩阵）
_KB: dict = {"hash": None, "ids": None, "mat": None}


def _kb_hash(items: list[dict]) -> str:
    raw = "\x00".join(f"{it['id']}\x01{_embed_text(it)}" for it in items)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_kb_matrix(items):
    """返回 (ids, mat, numpy) 若向量路径可用；否则 None。惰性 import numpy。"""
    if not items:
        return None
    if os.getenv("RAG_VECTOR", "1") == "0":   # 离线测试固定关键词路径
        return None
    try:
        import numpy as np
    except ImportError:
        return None
    from .llm import LLMClient
    client = LLMClient()
    if not client.available():
        return None
    h = _kb_hash(items)
    if _KB["hash"] == h and _KB.get("mat") is not None:
        return _KB["ids"], _KB["mat"], np
    with _KB_LOCK:
        # 双检：等锁期间可能已被其他线程构建
        if _KB["hash"] == h and _KB.get("mat") is not None:
            return _KB["ids"], _KB["mat"], np
        cache = DATA_VEC / f"kb_{h[:16]}.npz"
        if cache.exists():
            try:
                arr = np.load(cache)
                _KB.update(hash=h, ids=[str(x) for x in arr["ids"]], mat=arr["mat"])
                return _KB["ids"], _KB["mat"], np
            except Exception:
                pass
        try:
            vecs = client.embed([_embed_text(it) for it in items])
        except Exception:
            return None
        mat = np.asarray(vecs, dtype="float32")
        mat /= (np.linalg.norm(mat, axis=1, keepdims=True) + 1e-9)
        ids = [it["id"] for it in items]
        try:
            DATA_VEC.mkdir(parents=True, exist_ok=True)
            np.savez(cache, ids=np.array(ids, dtype="U64"), mat=mat)
        except OSError:
            pass
        _KB.update(hash=h, ids=ids, mat=mat)
        return ids, mat, np


def _vector_scores(query: str, items) -> dict[str, float]:
    got = _load_kb_matrix(items)
    if not got:
        return {}
    ids, mat, np = got
    from .llm import LLMClient
    try:
        qv = np.asarray(LLMClient().embed([_kb_query_vector(query)])[0], dtype="float32")
        qv /= (np.linalg.norm(qv) + 1e-9)
        sims = mat @ qv
    except Exception:
        return {}
    return {i: float(max(s, 0.0)) for i, s in zip(ids, sims)}


def retrieve(query: str, top_k: int = 5, items: list[dict] | None = None) -> list[dict]:
    """按代码特征检索最相关知识条目。

    有向量能力时：score = 0.5·归一化关键词分 + 0.5·余弦相似度；
    否则退化为纯关键词打分（分值为原始加权命中数）。
    """
    items = items if items is not None else load_knowledge()
    if not items:
        return []
    ql = query.lower()
    qwords = {w for w in re.findall(r"[a-z_]{3,}", ql) if w not in _STOP}
    kw = {it["id"]: _kw_score(ql, qwords, it) for it in items}
    vec = _vector_scores(query, items)
    scored: list[dict] = []
    if vec:
        mx = max(kw.values()) or 1.0
        for it in items:
            total = 0.5 * (kw[it["id"]] / mx) + 0.5 * vec.get(it["id"], 0.0)
            if total > 0.05:
                d = dict(it); d["score"] = round(total, 3); scored.append(d)
    else:
        for it in items:
            if kw[it["id"]] > 0:
                d = dict(it); d["score"] = round(kw[it["id"]], 1); scored.append(d)
    scored.sort(key=lambda x: -x["score"])
    return scored[:top_k]


def format_for_prompt(results: list[dict]) -> str:
    """把检索结果渲染成 Prompt 片段（附 ID 与来源，保证可解释、可溯源）。"""
    if not results:
        return "（本次未检索到相关知识条目）"
    blocks = []
    for it in results:
        blocks.append(
            f"### [{it['id']}] {it['title']}（严重度 {it.get('severity', '?')}，来源 {it.get('source', '未标注')}）\n"
            f"缺陷模式: {it.get('pattern', '')}\n"
            f"危害: {it.get('impact', '')}\n"
            f"修复要点: {it.get('fix', '')}"
        )
    return "\n\n".join(blocks)
