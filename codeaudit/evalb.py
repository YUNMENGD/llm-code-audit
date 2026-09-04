"""评测器：对照 examples/bench/manifest.json 计算 precision / recall / F1。

用法：
  python -m codeaudit eval examples/bench            # 完整审计（需密钥）
  python -m codeaudit eval examples/bench --static   # 仅静态规则（免费，验证评测器本身）
  python -m codeaudit eval examples/bench --runs 3   # 多轮（缓存使追加轮近似免费）+ 稳定性

匹配口径（v0.4 定稿，评测 README 有完整论述）：
1. 检测先按 (文件, 行号 ±2) 聚簇——模型常在同一行给多个 CWE 标签
   （如 eval 行被同时标 CWE-95/CWE-917），一个物理问题只算一次检测。
2. 只有含 security/logic 类问题的簇参与 P/R：style/engineering 属改进建议，
   ground truth 不标注它，计入 FP 会淹没真实误报信号。建议数单独报告。
3. 簇与 expected 按 (文件, 归一化CWE, 行区间重叠) 匹配；命中 → TP，
   未命中的缺陷簇 → FP；未被任何簇命中的 expected → FN。
验收：precision ≥ 0.8 且 recall ≥ 0.8（NFR-2）。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .retriever import load_knowledge
from .rules import load_rules
from .validate import _load_map

_TOL = 2
_DEFECT_CATS = ("security", "logic")


def _norm_cwe(rule_id: str, amap: dict) -> str:
    if rule_id in amap:
        return amap[rule_id]
    m = re.match(r"DISCOVERED-(CWE-\d+)", rule_id)
    return m.group(1) if m else rule_id


def load_manifest(bench_dir: Path) -> dict:
    return json.loads((bench_dir / "manifest.json").read_text(encoding="utf-8"))


def _cluster(issues) -> list:
    """同文件、行区间相距 ≤_TOL 的告警并为一个物理检测簇。"""
    by_file: dict[str, list] = {}
    for it in sorted(issues, key=lambda x: (x.path, x.line_start)):
        by_file.setdefault(it.path, []).append(it)
    clusters: list[list] = []
    for lst in by_file.values():
        cur = [lst[0]]
        for it in lst[1:]:
            if it.line_start - (cur[-1].line_end or cur[-1].line_start) <= _TOL + 1:
                cur.append(it)
            else:
                clusters.append(cur)
                cur = [it]
        if cur:
            clusters.append(cur)
    return clusters


def score_run(issues: list, manifest: dict, amap: dict) -> dict:
    """一次审计结果 vs manifest → 混淆明细（口径见模块 docstring）。"""
    expected = manifest["expected"]
    matched: set[int] = set()
    fp: list[str] = []
    advisory = 0
    for cl in _cluster(issues):
        cats = {i.category.value for i in cl}
        cwes = {_norm_cwe(i.rule_id, amap) for i in cl}
        lo = min(i.line_start for i in cl)
        hi = max(i.line_end or i.line_start for i in cl)
        path_name = Path(cl[0].path).name
        hit_idx = None
        for idx, e in enumerate(expected):
            if e["file"] != path_name or _norm_cwe(e["cwe"], amap) not in cwes:
                continue
            if lo <= e["line"] + _TOL and hi >= e["line"] - _TOL:
                hit_idx = idx
                break
        if hit_idx is not None:
            matched.add(hit_idx)
            continue
        if cats & set(_DEFECT_CATS):
            label = ",".join(sorted(_norm_cwe(i.rule_id, amap) for i in cl
                                    if i.category.value in _DEFECT_CATS))
            fp.append(f"{path_name}:{lo} {label} (x{len(cl)})")
        else:
            advisory += 1
    fn = [f"{e['file']}:{e['line']} {e['cwe']}"
          for idx, e in enumerate(expected) if idx not in matched]
    tp = len(matched)
    n_exp = len(expected)
    prec = tp / (tp + len(fp)) if (tp + len(fp)) else 1.0
    rec = tp / n_exp if n_exp else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "advisory": advisory,
            "precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(f1, 3)}


def run_eval(bench_dir: str | Path, *, static_only: bool = False,
             runs: int = 1, depth: str = "function",
             cross_review: bool | None = None) -> dict:
    """跑 runs 次审计并汇总（多轮均值 + 跨轮稳定性）。"""
    bench = Path(bench_dir)
    manifest = load_manifest(bench)
    amap = _load_map()
    per_run = []
    if static_only:
        from . import rules as RL
        all_rules = RL.load_rules()
        static_iss = []
        for f in sorted(bench.glob("*.py")):
            static_iss += RL.scan_source(
                f.read_text(encoding="utf-8"), all_rules, str(f))
        for _ in range(max(1, runs)):
            per_run.append(score_run(list(static_iss), manifest, amap))
    else:
        from .audit import audit_path
        for _r in range(max(1, runs)):
            rep = audit_path(bench, depth=depth, cross_review=cross_review)
            per_run.append(score_run(rep.issues, manifest, amap))
    keys = ("precision", "recall", "f1")
    avg = {k: round(sum(p[k] for p in per_run) / len(per_run), 3) for k in keys}
    stable = (len({json.dumps([p["tp"], sorted(p["fp"]), sorted(p["fn"])],
                              ensure_ascii=False) for p in per_run}) == 1)
    return {"runs": per_run, "avg": avg, "stable_across_runs": stable,
            "static_only": static_only}
