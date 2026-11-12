# -*- coding: utf-8 -*-
"""污点追踪真实库量化（论文实验节）：候选路径收集 + 人工核验 precision。

两阶段：
  --collect  在六个真实开源库上跑 TaintTracker，导出候选路径（附源码上下文）
             到 out/taint_candidates.json，供逐条人工核验；
  --report   读 bench-taint/annotations.json（T/F/? 判定）算 precision 与
             分库/分 sink 明细，写 docs/taint-eval-results.md。

口径（诚实声明）：候选路径是「静态近似提示」而非裁决——precision 度量
提示中真实数据流的比例。分层架构的设计就是静态层给证据、模型层做裁决，
本指标回答的是「证据层给模型引入了多少噪声」，与 bench-real 的告警
precision 口径一致（T/(T+F)，? 单列）。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codeaudit import realeval as RE                    # noqa: E402
from codeaudit import taint as TT                       # noqa: E402

ANNOT_FILE = ROOT / "bench-taint" / "annotations.json"
DOC_FILE = ROOT / "docs" / "taint-eval-results.md"


def collect() -> int:
    rows: list[dict] = []
    for lib in RE.LIBS:
        pkg = RE._pkg_dir(lib)
        if pkg is None:
            print(f"[{lib}] 跳过：未找到库源码（realtest/）")
            continue
        t0 = time.time()
        tt = TT.TaintTracker().build(pkg)
        seen: set = set()
        n0 = len(rows)
        for p in tt.paths:
            key = (p["file"], p["line"], p["call"])
            if key in seen:
                continue
            seen.add(key)
            f = Path(p["file"])
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            lo, hi = max(0, p["line"] - 6), min(len(lines), p["line"] + 5)
            ctx = "\n".join(f"{i + 1}| {lines[i]}" for i in range(lo, hi))
            rows.append({
                "lib": lib, "file": f.relative_to(pkg).as_posix(),
                "line": p["line"], "call": p["call"], "cwe": p["cwe"],
                "vars": p["vars"], "origin": p["origin"], "context": ctx})
        sinks = Counter(r["call"] for r in rows[n0:])
        print(f"[{lib}] 候选 {len(seen)} 条（去重后） stats={tt.stats()} "
              f"({time.time() - t0:.1f}s)  sink分布={dict(sinks.most_common(6))}")
    out = ROOT / "out" / "taint_candidates.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n共 {len(rows)} 条候选 → {out}")
    return 0


def report() -> int:
    if not ANNOT_FILE.exists():
        print(f"缺少核验标注：{ANNOT_FILE}（先 --collect 再逐条核验）")
        return 2
    doc = json.loads(ANNOT_FILE.read_text(encoding="utf-8"))
    rows = doc["annotations"]
    T = sum(1 for r in rows if r["verdict"] == "T")
    F = sum(1 for r in rows if r["verdict"] == "F")
    Q = sum(1 for r in rows if r["verdict"] == "?")
    prec = round(T / (T + F), 3) if (T + F) else None
    per_lib: dict[str, Counter] = {}
    per_sink: dict[str, Counter] = {}
    for r in rows:
        per_lib.setdefault(r["lib"], Counter())[r["verdict"]] += 1
        per_sink.setdefault(r["call"], Counter())[r["verdict"]] += 1
    lines = [
        "# 污点追踪真实库量化实验", "",
        f"- 日期：{time.strftime('%Y-%m-%d')}",
        "- 对象：bench-real 同款六个真实开源库（botocore/click/flask/requests/trio/werkzeug）",
        "- 方法：TaintTracker（source/sink 目录 + 调用图迭代传播）产出候选路径，"
        "逐条读源码上下文人工核验 T（真实数据流）/ F（近似误报）/ ?（存疑）",
        f"- 口径：precision = T/(T+F) = **{prec}**（T={T} / F={F} / ?={Q}，? 单列不计入）",
        "",
        "> 候选路径是静态近似「提示」而非裁决：分层架构中静态层给证据、LLM 层做语义裁决。",
        "> 本指标度量证据层噪声水平，与 bench-real 告警 precision 口径一致。",
        "",
        "## 分库明细", "",
        "| 库 | T | F | ? | precision |", "| --- | --- | --- | --- | --- |",
    ]
    for lib, c in sorted(per_lib.items()):
        p = round(c["T"] / (c["T"] + c["F"]), 3) if (c["T"] + c["F"]) else "—"
        lines.append(f"| {lib} | {c['T']} | {c['F']} | {c['?']} | {p} |")
    lines += ["", "## 分 sink 明细", "",
              "| sink | T | F | ? |", "| --- | --- | --- | --- |"]
    for call, c in sorted(per_sink.items(), key=lambda kv: -sum(kv[1].values())):
        lines.append(f"| {call} | {c['T']} | {c['F']} | {c['?']} |")
    lines += ["", "## 误报模式归纳", ""]
    patterns = Counter(r.get("pattern", "?") for r in rows if r["verdict"] == "F")
    for pat, n in patterns.most_common():
        lines.append(f"- {pat}: {n} 条")
    lines += ["", "## 核验标注全文", "",
              "| 库 | 位置 | sink | 判定 | 依据 |", "| --- | --- | --- | --- | --- |"]
    for r in rows:
        lines.append(f"| {r['lib']} | {r['file']}:{r['line']} | {r['call']} "
                     f"| {r['verdict']} | {r.get('note', '')} |")
    lines.append("")
    DOC_FILE.parent.mkdir(exist_ok=True)
    DOC_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"precision={prec} (T={T}/F={F}/?={Q}) → {DOC_FILE}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--collect", action="store_true")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    if a.collect:
        return collect()
    if a.report:
        return report()
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
