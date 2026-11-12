# -*- coding: utf-8 -*-
"""RAG 消融实验：关键词检索 vs 向量融合检索（论文实验章数据）。

方法论：
- 真值 = bench-real 六库人工核验标注中 verdict=T 的告警（真缺陷），
  经 cwe_map 把规则 ID 映射到知识条目 ID——「审计这段代码时，正确的
  弹药条目有没有被检索进 top-k」即 recall@k；
- 查询口径与 audit._audit_unit 完全一致（源码前 3000 字符 + 导入词，
  scope=全文做否决），保证实验测的就是线上行为；
- 两臂：RAG_VECTOR=0 纯关键词（离线可跑）；RAG_VECTOR=1 向量融合
  （需 EMBEDDING_* 或主配置具备 embeddings 能力，否则该臂如实标注不可用）；
- 附加指标：F 标注（已确认误报）对应条目的 top-k 命中率——越低越好，
  但注意 veto 机制本就会剔除部分越界条目，两臂同口径对比才公平。

用法：python tools/rag_ablation.py [--k 5] [--out docs/rag-ablation-results.md]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codeaudit import retriever as R                    # noqa: E402
from codeaudit.realeval import LIBS, _pkg_dir, load_gt  # noqa: E402

CWE_MAP = json.loads((ROOT / "knowledge" / "rules" / "cwe_map.json")
                     .read_text(encoding="utf-8"))["map"]
# 实验口径护栏：映射目标必须真实存在于知识库，否则该用例剔除并记录
# （防止「映射到不存在的条目」造成 recall 恒 0 的假结论）
_KB_IDS = {it["id"] for it in R.load_knowledge()}
BAD_MAP = {k: v for k, v in CWE_MAP.items() if v not in _KB_IDS}
CWE_MAP = {k: v for k, v in CWE_MAP.items() if v in _KB_IDS}


def _cases() -> tuple[list[dict], list[dict]]:
    """从六库标注构造评测用例，返回 (可评用例, 窗口外用例)。

    两种查询口径（都与线上行为对齐）：
    - file 窗：源码前 3000 字符（audit._audit_unit 的文件级打分窗口）；
      告警行落在窗口内才可评——窗口外的行线上文件级审计同样看不到，
      记为「窗口外」单列，不混入 recall 分母（否则测的是窗口覆盖率而非检索）。
    - func 窗：告警行所在函数的完整源码（函数级审计的真实查询形态），
      作为第二口径对照，量化粒度选择对检索召回的影响。
    """
    import ast
    cases, out_of_window = [], []
    for lib in LIBS:
        gt = load_gt(lib)
        pkg = _pkg_dir(lib)
        if gt is None or pkg is None:
            continue
        for a in gt["annotations"]:
            if a["verdict"] not in ("T", "F"):
                continue
            kid = CWE_MAP.get(a["rule"])
            if not kid:
                continue
            f = pkg / a["file"]
            if not f.exists():
                continue
            src = f.read_text(encoding="utf-8", errors="replace")
            lines = src.splitlines()
            offset = len("\n".join(lines[:a["line"] - 1]))
            base = {"lib": lib, "file": a["file"], "line": a["line"],
                    "rule": a["rule"], "kid": kid, "verdict": a["verdict"]}
            if offset < 3000:
                cases.append({**base, "src": src, "query": src[:3000],
                              "scope": src, "window": "file"})
            else:
                out_of_window.append(base)
            # func 窗口径：找包含告警行的函数
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end = getattr(node, "end_lineno", node.lineno)
                    if node.lineno <= a["line"] <= end:
                        fsrc = "\n".join(lines[node.lineno - 1:end])
                        cases.append({**base, "src": fsrc,
                                      "query": fsrc[:3000], "scope": fsrc,
                                      "window": "func"})
                        break
    return cases, out_of_window


def _run_arm(cases: list[dict], k: int, vector: bool) -> dict:
    os.environ["RAG_VECTOR"] = "1" if vector else "0"
    # 清内存缓存，避免两臂串味
    with R._KB_LOCK:
        R._KB.update(hash=None, ids=None, mat=None)
    items = R.load_knowledge()
    t0 = time.time()
    t_hit = t_tot = f_hit = f_tot = 0
    per_lib: dict[str, dict] = {}
    misses = []
    for c in cases:
        hits = R.retrieve(c["query"], top_k=k, items=items, scope=c["scope"])
        got = c["kid"] in {h["id"] for h in hits}
        pl = per_lib.setdefault(c["lib"], {"t_hit": 0, "t_tot": 0,
                                           "f_hit": 0, "f_tot": 0})
        if c["verdict"] == "T":
            t_tot += 1
            pl["t_tot"] += 1
            if got:
                t_hit += 1
                pl["t_hit"] += 1
            else:
                misses.append(f"{c['lib']}/{c['file']}:{c['line']} "
                              f"{c['rule']}→{c['kid']}")
        else:
            f_tot += 1
            pl["f_tot"] += 1
            if got:
                f_hit += 1
                pl["f_hit"] += 1
    return {"arm": "vector-fusion" if vector else "keyword-only",
            "k": k, "t_hit": t_hit, "t_tot": t_tot,
            "recall_at_k": round(t_hit / t_tot, 3) if t_tot else None,
            "f_hit": f_hit, "f_tot": f_tot,
            "f_rate": round(f_hit / f_tot, 3) if f_tot else None,
            "elapsed_sec": round(time.time() - t0, 1),
            "per_lib": per_lib, "t_misses": misses}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--out", default=str(ROOT / "docs" / "rag-ablation-results.md"))
    a = ap.parse_args()

    cases, oow = _cases()
    if not cases:
        print("无可用评测用例：需要 bench-real 标注 + realtest/ 库源码")
        return 2
    file_cases = [c for c in cases if c["window"] == "file"]
    func_cases = [c for c in cases if c["window"] == "func"]

    # 向量臂可用性判定：显式 EMBEDDING_* 或主服务商具备 embeddings
    from codeaudit.llm import LLMClient
    client = LLMClient()
    embed_ready = bool(os.getenv("EMBEDDING_API_KEY", "").strip())
    if not embed_ready and client.available():
        try:
            client.embed(["probe"])
            embed_ready = True
        except Exception:
            embed_ready = False

    results = {}
    for wname, subset in (("file", file_cases), ("func", func_cases)):
        if not subset:
            continue
        n_t = sum(1 for c in subset if c["verdict"] == "T")
        print(f"\n[{wname} 窗] 用例 {len(subset)} 条（T={n_t}），k={a.k}")
        kw = _run_arm(subset, a.k, vector=False)
        print(f"  关键词臂 recall@{a.k}={kw['recall_at_k']} "
              f"({kw['t_hit']}/{kw['t_tot']})  F命中={kw['f_hit']}/{kw['f_tot']}")
        vec = None
        if embed_ready:
            vec = _run_arm(subset, a.k, vector=True)
            print(f"  向量融合臂 recall@{a.k}={vec['recall_at_k']} "
                  f"({vec['t_hit']}/{vec['t_tot']})  F命中={vec['f_hit']}/{vec['f_tot']}")
        results[wname] = {"keyword": kw, "vector": vec, "n_cases": len(subset)}
    if not embed_ready:
        print("\n[向量融合臂] 不可用：当前服务商无 embeddings 接口且未配置 "
              "EMBEDDING_API_KEY（如实标注，不编造数据）")

    lines = [
        "# RAG 消融实验：关键词 vs 向量融合",
        "",
        f"- 日期：{time.strftime('%Y-%m-%d')} · k={a.k}",
        "- 真值：bench-real 六库人工核验 T/F 标注，规则→知识条目经 cwe_map 映射"
        "（映射目标必须真实存在于知识库，坏映射已剔除）",
        f"- 窗口外用例：{len(oow)} 条 T/F 告警行落在文件级 3000 字符打分窗之外，"
        "单列不计入 recall 分母（线上文件级审计同样看不到这些行；函数级口径可覆盖）",
        "",
        "| 查询口径 | 臂 | recall@k（T 命中） | F 条目 top-k 命中率 | 耗时 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for wname, r in results.items():
        kw, vec = r["keyword"], r["vector"]
        wlabel = "文件窗（前3000字符）" if wname == "file" else "函数窗（所在函数全文）"
        lines.append(f"| {wlabel} | 关键词 | {kw['recall_at_k']} "
                     f"({kw['t_hit']}/{kw['t_tot']}) | {kw['f_rate']} "
                     f"({kw['f_hit']}/{kw['f_tot']}) | {kw['elapsed_sec']}s |")
        if vec:
            lines.append(f"| {wlabel} | 向量融合 | {vec['recall_at_k']} "
                         f"({vec['t_hit']}/{vec['t_tot']}) | {vec['f_rate']} "
                         f"({vec['f_hit']}/{vec['f_tot']}) | {vec['elapsed_sec']}s |")
        else:
            lines.append(f"| {wlabel} | 向量融合 | ⚠️暂未获取（无 embeddings 端点） | — | — |")
    for wname, r in results.items():
        kw = r["keyword"]
        lines += ["", f"## 分库明细（{wname} 窗 · 关键词臂）", "",
                  "| 库 | T 命中/总数 | F 命中/总数 |", "| --- | --- | --- |"]
        for lib, d in sorted(kw["per_lib"].items()):
            lines.append(f"| {lib} | {d['t_hit']}/{d['t_tot']} | {d['f_hit']}/{d['f_tot']} |")
        if kw["t_misses"]:
            lines += ["", f"### {wname} 窗未命中的 T 用例（向量臂的潜在增益点）", ""]
            lines += [f"- {m}" for m in kw["t_misses"][:30]]
    lines += ["", "> 口径说明：本实验测「检索层把正确弹药送进 top-k 的能力」，"
              "不是端到端 precision；F 命中率仅作参考——veto 机制会剔除越界条目，"
              "两臂同口径。窗口外用例单列是诚实口径：文件级打分窗截断是线上真实行为，"
              "函数级粒度可覆盖长文件后部的告警行。向量臂数据缺失时不得以训练知识补全。", ""]
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    (ROOT / "out").mkdir(exist_ok=True)
    (ROOT / "out" / "rag_ablation.json").write_text(
        json.dumps({"results": results, "out_of_window": oow},
                   ensure_ascii=False, indent=1),
        encoding="utf-8")
    print(f"\n结果已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
