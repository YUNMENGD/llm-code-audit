"""评测器：对照 examples/bench/manifest.json 计算 precision / recall / F1。

用法：
  python -m codeaudit eval examples/bench            # 完整审计（需密钥）
  python -m codeaudit eval examples/bench --static   # 仅静态规则（免费，验证评测器本身）
  python -m codeaudit eval examples/bench --runs 3   # 多轮（缓存使追加轮近似免费）+ 一致性

匹配口径：同文件 + 行区间重叠（±2 容差）+ 归一化 CWE 相同（cwe_map / DISCOVERED-CWE-x）。
预期外检出 → FP；预期未被命中 → FN。验收：precision ≥ 0.8（NFR-2）。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .rules import load_rules
from .retriever import load_knowledge
from .validate import _load_map

_TOL = 2


def _norm_cwe(rule_id: str, amap: dict) -> str:
    if rule_id in amap:
        return amap[rule_id]
    m = re.match(r"DISCOVERED-(CWE-\d+)", rule_id)
    return m.group(1) if m else rule_id


def load_manifest(bench_dir: Path) -> dict:
    return json.loads((bench_dir / "manifest.json").read_text(encoding="utf-8"))


def score_run(issues: list, manifest: dict, amap: dict) -> dict:
    """把一次审计的 Issue 列表与 manifest 对照，返回混淆明细。"""
    expected = manifest["expected"]
    matched: set[int] = set()
    fps: list[str] = []
    for it in issues:
        fname = Path(it.path).name
        cwe = _norm_cwe(it.rule_id, amap)
        ok = False
        for idx, e in enumerate(expected):
            if e["file"] != fname or _norm_cwe(e["cwe"], amap) != cwe:
                continue
            lo = e["line"] - _TOL
            hi = e["line"] + _TOL
            if it.line_start <= hi and (it.line_end or it.line_start) >= lo:
                matched.add(idx)
                ok = True
                break
        if not ok:
            fps.append(f"{fname}:{it.line_start} {it.rule_id} ({cwe})")
    fn = [f"{e['file']}:{e['line']} {e['cwe']}"
          for idx, e in enumerate(expected) if idx not in matched]
    tp = len(matched)
    n_exp = len(expected)
    prec = tp / (tp + len(fps)) if (tp + len(fps)) else 1.0
    rec = tp / n_exp if n_exp else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"tp": tp, "fp": fps, "fn": fn,
            "precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(f1, 3)}


def run_eval(bench_dir: str | Path, *, static_only: bool = False,
             runs: int = 1, depth: str = "function",
             cross_review: bool | None = None) -> dict:
    """跑 runs 次完整审计并汇总（含多轮均值与稳定性）。"""
    from .audit import audit_path
    from . import rules as RL
    bench = Path(bench_dir)
    manifest = load_manifest(bench)
    amap = _load_map()
    per_run = []
    if static_only:
        all_rules = RL.load_rules()
        static_iss = []
        for f in sorted(bench.glob("*.py")):
            static_iss += RL.scan_source(
                f.read_text(encoding="utf-8"), all_rules, str(f))
        for _ in range(max(1, runs)):
            per_run.append(score_run(list(static_iss), manifest, amap))
    else:
        for _r in range(max(1, runs)):
            rep = audit_path(bench, depth=depth, cross_review=cross_review)
            per_run.append(score_run(rep.issues, manifest, amap))
    avg = {k: round(sum(p[k] for p in per_run) / len(per_run), 3)
           for k in ("precision", "recall", "f1")}
    stable = (len({json.dumps(p["fn"], ensure_ascii=False) for p in per_run}) == 1)
    return {"runs": per_run, "avg": avg, "stable_across_runs": stable,
            "static_only": static_only}
