"""缺陷知识库检索（RAG）。

D12 前：关键词打分检索（本实现，零依赖，接口已按向量检索设计好）。
D12 后：换成 embedding + chromadb，retrieve() 签名不变，audit 模块无感知。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge" / "defects"

_STOP = {"the", "and", "for", "with", "that", "this", "def", "return", "class",
         "import", "from", "self", "none", "true", "false", "if", "else", "try"}


def load_knowledge() -> list[dict]:
    items: list[dict] = []
    if not KNOWLEDGE_DIR.exists():
        return items
    for f in sorted(KNOWLEDGE_DIR.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        items.extend(data.get("items", []))
    return items


def retrieve(query: str, top_k: int = 5, items: list[dict] | None = None) -> list[dict]:
    """按代码特征检索最相关的知识条目。

    打分：trigger 词命中 3 分、tags 命中 2 分、title 分词命中 1 分。
    返回条目带 score 字段，供 Prompt 拼接与可解释展示。
    """
    items = items if items is not None else load_knowledge()
    ql = query.lower()
    qwords = {w for w in re.findall(r"[a-z_]{3,}", ql) if w not in _STOP}
    scored: list[tuple[float, dict]] = []
    for it in items:
        s = 0.0
        for t in it.get("triggers", []):
            if t.lower() in ql:
                s += 3
        for tag in it.get("tags", []):
            if tag.lower() in qwords:
                s += 2
        for w in re.findall(r"[a-z_]{3,}", it.get("title", "").lower()):
            if w in qwords:
                s += 1
        if s > 0:
            scored.append((s, it))
    scored.sort(key=lambda x: -x[0])
    out = []
    for s, it in scored[:top_k]:
        it = dict(it)
        it["score"] = round(s, 1)
        out.append(it)
    return out


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
