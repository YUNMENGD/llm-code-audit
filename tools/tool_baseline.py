# -*- coding: utf-8 -*-
"""第三方静态分析工具基线对比（A 实验：论文"相较于通用工具"主张的数据支撑）。

方法：与 bench-real 同一把尺子——
  · 尺子：六库 125 条 GT 中 SEC/LOG 规则的标注行（R-SEC-*/R-LOG-*；
    TODO/ENG 类缺陷 bandit 等根本不支持，纳入会误导，口径写明）
  · 匹配：工具告警与 GT 标注 (文件,行) ±3 行内命中 → 继承人工 verdict
  · 指标：
      P_命中 = 命中GT的部分里 T/(T+F)      —— 报出来的东西有多可信
      覆盖   = GT 中 T 行被工具命中的比例   —— 已知真缺陷的查全（仅相对GT）
      洪泛   = 允许文件集内、GT 之外的告警总数 —— 人工要消化多少噪声
  · 本引擎用 _current_hits（治理后）走完全相同的流程，同表对照。

用法：python tools/tool_baseline.py [--libs click,trio] [--skip semgrep]
产物：out/tool_baseline.json（明细可重放）+ 控制台汇总表
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codeaudit import rules as RL                    # noqa: E402
from codeaudit.realeval import (_EXCLUDE, _current_hits, _pkg_dir,  # noqa: E402
                                load_gt, LIBS)

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
WINDOW = 3                     # 与 validate.verify 同口径
TOOLS = ("bandit", "semgrep", "pylint", "ours")


def allowed_files(pkg: Path) -> set[str]:
    out = set()
    for f in pkg.rglob("*.py"):
        parts = {p.lower() for p in f.resolve().parts}
        if _EXCLUDE & parts or f.name.startswith(("test_", "tests_")):
            continue
        out.add(f.resolve().as_posix().lower())
    return out


def gt_lines(lib: str) -> dict[str, dict[int, dict]]:
    """file → {line: anno}，只取 SEC/LOG 规则标注。"""
    gt = load_gt(lib)
    m: dict[str, dict[int, dict]] = {}
    for a in gt["annotations"]:
        if a["rule"].startswith(("R-SEC", "R-LOG")):
            m.setdefault(a["file"], {})[a["line"]] = a
    return m


def match_hits(pkg: Path, dets: list[tuple], gmap) -> dict:
    """dets: (path, line, tool_rule)。归一相对路径后 ±WINDOW 匹配 GT。"""
    rel_set = {p: None for f in pkg.rglob("*.py")
               for p in [f.relative_to(pkg).as_posix()]}
    hits: dict[tuple, str] = {}          # (file,line)→verdict
    flood_list: list[dict] = []
    flood = 0
    for path, line, trule in dets:
        p = Path(path)
        try:
            rel = p.resolve().relative_to(pkg).as_posix()
        except (ValueError, OSError):
            rel = p.name
        if rel not in rel_set:
            continue                      # 测试/文档目录外的不算（洪泛基数一致）
        near = {ln: ann for ln, ann in gmap.get(rel, {}).items()
                if abs(ln - line) <= WINDOW}
        if near:
            ann = min(near, key=lambda ln: abs(ln - line))
            key = (rel, ann)
            if key not in hits:
                hits[key] = near[ann]["verdict"]
        else:
            flood += 1
            flood_list.append({"file": rel, "line": line, "tool_rule": trule})
    t = sum(1 for v in hits.values() if v == "T")
    f_ = sum(1 for v in hits.values() if v == "F")
    q = sum(1 for v in hits.values() if v == "?")
    n_t = sum(1 for fs in gmap.values() for a in fs.values() if a["verdict"] == "T")
    return {"matched": len(hits), "T": t, "F": f_, "Q": q,
            "P": round(t / (t + f_), 3) if t + f_ else None,
            "T_covered": t, "T_total": n_t,
            "flood_unannotated": flood,
            "flood_list": flood_list,
            "detail": [{"file": k[0], "line": k[1], "verdict": v}
                       for k, v in sorted(hits.items())]}


def run_bandit(files: list[str]) -> list[tuple[str, int]]:
    if not files:
        return []
    r = subprocess.run(
        [PY, "-m", "bandit", "-q", "-f", "json", *files],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        d = json.loads(r.stdout or "{}")
        return [(x["filename"], x["line_number"], x.get("test_id", "?"))
                for x in d.get("results", [])]
    except json.JSONDecodeError:
        return []


def run_semgrep(files: list[str]) -> list[tuple]:
    if not files:
        return []
    exe = Path(PY).parent / "Scripts" / "semgrep.exe"
    cmd = [str(exe), "scan", "--config", "p/default", "--json",
           "--metrics", "off", "--quiet", "--no-git-ignore", *files]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=3600)
    try:
        d = json.loads(r.stdout or "{}")
        return [(x["path"], x["start"]["line"], x["check_id"].split(".")[-1])
                for x in d.get("results", [])]
    except json.JSONDecodeError:
        return []


def run_pylint(files: list[str]) -> list[tuple[str, int]]:
    if not files:
        return []
    # 只开与 SEC/LOG 标注同语义的检查，避免拿风格噪声冒充检测能力
    codes = ("W0122,W0123,W0702,W0703,W0718,W0705,"   # exec/eval/宽捕获/裸except
             "W1514,W1508,W0715,W1510")
    r = subprocess.run(
        [PY, "-m", "pylint", "--output-format=json", "--persistent=n",
         f"--disable=all", f"--enable={codes}", *files],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=3600)
    try:
        d = json.loads(r.stdout or "[]")
        return [(x["path"], x["line"], x.get("message-id", "?").strip("*"))
                for x in d if isinstance(x, dict)]
    except json.JSONDecodeError:
        return []


def run_ours(pkg: Path) -> list[tuple]:
    out = []
    for h in _current_hits(pkg):
        if h.rule_id.startswith(("R-SEC", "R-LOG")):
            out.append((str(pkg / h.path), h.line_start, h.rule_id))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--libs", default="")
    ap.add_argument("--skip", default="", help="逗号分隔: bandit,semgrep,pylint")
    a = ap.parse_args()
    libs = a.libs.split(",") if a.libs else LIBS
    skip = set(a.skip.split(","))
    runners = {k: v for k, v in
               {"bandit": run_bandit, "semgrep": run_semgrep,
                "pylint": run_pylint}.items() if k not in skip}

    result: dict[str, dict] = {}
    for lib in libs:
        pkg = _pkg_dir(lib)
        if pkg is None:
            print(f"[{lib}] 无源码目录，跳过")
            continue
        gmap = gt_lines(lib)
        files = [str(f.resolve()) for f in sorted(pkg.rglob("*.py"))
                 if f.resolve().as_posix().lower() in allowed_files(pkg)]
        print(f"[{lib}] {len(files)} 文件, GT(SEC/LOG) {sum(len(v) for v in gmap.values())} 行")
        per_tool: dict[str, dict] = {}
        for name, fn in runners.items():
            try:
                dets = fn(files)
            except subprocess.TimeoutExpired:
                dets = []
                print(f"  {name}: 超时")
            per_tool[name] = match_hits(pkg, dets, gmap)
            print(f"  {name:8s} 总告警{sum(1 for _ in dets):4d} | 命中GT "
                  f"{per_tool[name]['matched']:2d} (T{per_tool[name]['T']}"
                  f"/F{per_tool[name]['F']}/?{per_tool[name]['Q']}) "
                  f"P={per_tool[name]['P']} 洪泛{per_tool[name]['flood_unannotated']}")
        per_tool["ours"] = match_hits(pkg, run_ours(pkg), gmap)
        o = per_tool["ours"]
        print(f"  {'ours':8s} 命中GT {o['matched']:2d} (T{o['T']}/F{o['F']}"
              f"/?{o['Q']}) P={o['P']} 洪泛{o['flood_unannotated']}")
        result[lib] = per_tool

    agg = {}
    for tool in TOOLS:
        rows = [r[tool] for r in result.values() if tool in r]
        if not rows:
            continue
        T = sum(r["T"] for r in rows); F = sum(r["F"] for r in rows)
        agg[tool] = {"T": T, "F": F, "P": round(T / (T + F), 3) if T + F else None,
                     "matched": sum(r["matched"] for r in rows),
                     "flood": sum(r["flood_unannotated"] for r in rows),
                     "T_covered": sum(r["T_covered"] for r in rows),
                     "T_total": sum(r["T_total"] for r in rows)}
    print("\n=== 六库汇总（SEC/LOG 标注口径）===")
    for tool, s in agg.items():
        print(f"{tool:8s} P={s['P']}  T覆盖 {s['T_covered']}/{s['T_total']}"
              f"  命中 {s['matched']}  洪泛(GT外未标注) {s['flood']}")
    out = ROOT / "out" / "tool_baseline.json"
    out.write_text(json.dumps({"libs": result, "agg": agg,
                               "method": {"window": WINDOW,
                                          "scope": "SEC/LOG GT lines",
                                          "pylint_codes": "W0122,W0123,W0702,W0703,W0718,W0705,W1514,W1508,W0715,W1510"}},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n明细 → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
