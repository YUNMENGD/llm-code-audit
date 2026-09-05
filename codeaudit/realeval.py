"""真实开源库基准评测（任务A）：只测 precision，不测 recall。

为什么与合成 eval（evalb.py）分开：
- 合成基准能测 recall——预埋缺陷是已知的，漏没漏一目了然。
- 真实成熟库的「真缺陷」近乎为零且无法穷举标注（我们没能力断言 click 没有未知漏洞），
  因此 ground truth 是「系统报出的每条告警，人工判 T/F/?」，只能算 precision
  = T / (T + F)，? 单列不计入。recall 无从谈起，方法论上就不该假装有。
两套基准互补：合成保下限（不漏真缺陷），真实保上限（不制造噪声）。

ground truth 见 bench-real/<lib>.json：对「治理前基线」的全量告警逐行判定。
本评测把「当前代码的扫描结果」与该基线对照，量化治理带来的 precision 提升。
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from . import rules as RL

_ROOT = Path(__file__).resolve().parent.parent
_REALTEST = _ROOT.parent / "realtest"
_BENCH = _ROOT / "bench-real"
_EXCLUDE = {"tests", "test", "_tests", "testing", "docs", "doc", "_vendor",
            ".venv", "scripts", "example", "examples", "build", "dist"}


def load_gt(lib: str) -> dict | None:
    f = _BENCH / f"{lib}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


def _pkg_dir(lib: str) -> Path | None:
    base = _REALTEST / lib
    if not base.exists():
        return None
    sub = (base / "src")
    root = sub if sub.exists() else base
    for d in sorted(root.iterdir()):
        if d.is_dir() and (d / "__init__.py").exists() \
                and d.name.lower() not in _EXCLUDE:
            return d
    return None


def _current_hits(pkg: Path) -> list[RL.Issue]:
    rs = RL.load_rules()
    hits: list[RL.Issue] = []
    for f in sorted(pkg.rglob("*.py")):
        parts = {p.lower() for p in f.resolve().parts}
        if _EXCLUDE & parts or f.name.startswith(("test_", "tests_")):
            continue
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = f.relative_to(pkg).as_posix()
        hits += RL.scan_source(src, rs, rel)
    return hits


def evaluate(lib: str) -> dict:
    """把当前扫描结果与治理前 ground truth 对照，算 precision 与降噪。"""
    gt = load_gt(lib)
    if gt is None:
        return {"lib": lib, "error": f"无 ground truth：bench-real/{lib}.json"}
    pkg = _pkg_dir(lib)
    if pkg is None:
        return {"lib": lib, "error": f"未找到库目录：realtest/{lib}（按 clone 字段下载）"}

    annos = gt["annotations"]
    # ground truth 键：(file, line, rule) → verdict
    gt_map = {(a["file"], a["line"], a["rule"]): a["verdict"] for a in annos}
    gt_T = sum(1 for v in gt_map.values() if v == "T")
    gt_F = sum(1 for v in gt_map.values() if v == "F")
    gt_q = sum(1 for v in gt_map.values() if v == "?")
    baseline_total = len(annos)
    baseline_p = round(gt_T / (gt_T + gt_F), 3) if (gt_T + gt_F) else None

    # 当前扫描结果，对照 ground truth 判定（命中行仍用原判定；新出现的行标 ?）
    cur = _current_hits(pkg)
    cur_keys = {(h.path, h.line_start, h.rule_id) for h in cur}
    still_fp = 0     # 治理前判 F、当前仍报 → 残留误报
    removed_fp = 0   # 治理前判 F、当前已消 → 成功降噪
    kept_T = 0       # 治理前判 T、当前仍报 → 真缺陷未被误杀（关键安全指标）
    lost_T = 0       # 治理前判 T、当前不报 → 危险：可能过度抑制
    novel = []       # ground truth 没有的新告警（库版本差异或治理副作用）
    for (f, line, rule), verdict in gt_map.items():
        present = (f, line, rule) in cur_keys
        if verdict == "F":
            if present:
                still_fp += 1
            else:
                removed_fp += 1
        elif verdict == "T":
            if present:
                kept_T += 1
            else:
                lost_T += 1
    for k in cur_keys - set(gt_map):
        novel.append(k)

    cur_fp = still_fp
    cur_t = kept_T
    cur_p = round(cur_t / (cur_t + cur_fp), 3) if (cur_t + cur_fp) else None

    return {
        "lib": lib,
        "baseline": {"total": baseline_total, "T": gt_T, "F": gt_F, "?": gt_q,
                     "precision": baseline_p},
        "current": {"total": len(cur), "still_fp": still_fp,
                    "removed_fp": removed_fp, "kept_T": kept_T,
                    "lost_T": lost_T, "precision": cur_p,
                    "novel": len(novel)},
        "pattern_fp_removed": _removed_by_pattern(gt, cur_keys),
        "novel_hits": [f"{a}:{b} {c}" for a, b, c in sorted(novel)],
    }


def _removed_by_pattern(gt: dict, cur_keys: set) -> dict:
    """统计各误报模式被消除的数量，验证治理是否打在靶心上。"""
    cnt: Counter = Counter()
    for a in gt["annotations"]:
        key = (a["file"], a["line"], a["rule"])
        if a["verdict"] == "F" and key not in cur_keys:
            cnt[a.get("pattern", "?")] += 1
    return dict(cnt.most_common())


def main(libs: list[str]) -> int:
    if not libs:
        libs = sorted(p.stem for p in _BENCH.glob("*.json"))
    all_ok = True
    for lib in libs:
        r = evaluate(lib)
        if "error" in r:
            print(f"[{lib}] {r['error']}")
            all_ok = False
            continue
        b, c = r["baseline"], r["current"]
        print(f"=== {lib} ===")
        print(f"  基线(治理前): {b['total']} 条  T{b['T']}/F{b['F']}/?{b['?']}"
              f"  precision={b['precision']}")
        print(f"  当前(治理后): {c['total']} 条  precision={c['precision']}")
        print(f"  降噪: 误报 −{c['removed_fp']}（残留 {c['still_fp']}）"
              f" | 真缺陷保留 {c['kept_T']}/{b['T']}（误杀 {c['lost_T']}）")
        if r["pattern_fp_removed"]:
            print(f"  消除的误报按模式: {r['pattern_fp_removed']}")
        if c["novel"]:
            print(f"  ⚠ 新增告警 {c['novel']} 条（gt 外）: {r['novel_hits'][:5]}")
        if c["lost_T"] > 0:
            print("  ❌ 有真缺陷被误杀，治理过度！")
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
