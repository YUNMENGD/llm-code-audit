# -*- coding: utf-8 -*-
"""静态扫描性能实测：串行 vs 进程池并行（论文性能数据）。

在真实库（realtest/）或指定目录上跑两种模式，校验结果逐条一致后计时，
写 docs/perf-scan-results.md。用法：
  python tools/perf_scan.py            # 六库全量
  python tools/perf_scan.py click      # 指定库
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codeaudit import jsrules as JR                     # noqa: E402
from codeaudit import parallel as PL                    # noqa: E402
from codeaudit import realeval as RE                    # noqa: E402
from codeaudit import rules as RL                       # noqa: E402


def _files(pkg: Path) -> list[Path]:
    return sorted(p for p in pkg.rglob("*")
                  if p.is_file() and p.suffix in ({".py"} | JR.JS_EXTS)
                  and not any(x in p.parts for x in
                              (".git", "__pycache__", ".venv", "venv", "node_modules")))


def _serial(files: list[Path]) -> list:
    rs, js = RL.load_rules(), JR.load_js_rules()
    out = []
    for f in files:
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if f.suffix in JR.JS_EXTS:
            out += JR.scan_js_source(src, js, str(f))
        else:
            out += RL.scan_source(src, rs, str(f))
    out.sort(key=lambda i: (i.path, i.rule_id, i.line_start))
    return out


def _key(issues: list) -> list:
    return [(i.path, i.rule_id, i.line_start) for i in issues]


def main(libs: list[str]) -> int:
    libs = libs or RE.LIBS
    rows = []
    for lib in libs:
        pkg = RE._pkg_dir(lib)
        if pkg is None:
            print(f"[{lib}] 跳过：未找到库源码")
            continue
        files = _files(pkg)
        t0 = time.perf_counter()
        ser = _serial(files)
        t_ser = time.perf_counter() - t0
        t0 = time.perf_counter()
        # 强制并行测量（保留原始对照数据）；生产默认走 default_workers 阈值
        par, skipped = PL.scan_files_parallel(files, workers=max(2, min(8, (__import__("os").cpu_count() or 4) - 1)))
        t_par = time.perf_counter() - t0
        same = _key(ser) == _key(par)
        speedup = round(t_ser / t_par, 2) if t_par > 0 else None
        rows.append({"lib": lib, "files": len(files), "issues": len(ser),
                     "serial_sec": round(t_ser, 2), "parallel_sec": round(t_par, 2),
                     "speedup": speedup, "identical": same, "skipped": skipped,
                     "workers": PL.default_workers(len(files))})
        print(f"[{lib}] {len(files)} 文件 / {len(ser)} 告警  "
              f"串行 {t_ser:.2f}s → 并行 {t_par:.2f}s (×{speedup})  "
              f"结果一致={same}")
        if not same:
            print("  ❌ 并行结果与串行不一致！")
    if not rows:
        return 2
    lines = ["# 静态扫描性能实测：串行 vs 进程池并行", "",
             f"- 日期：{time.strftime('%Y-%m-%d')} · 机器 CPU {__import__('os').cpu_count()} 核"
             f" · workers={rows[0]['workers']}",
             "- 一致性校验：并行与串行结果按 (path, rule, line) 逐条对齐，全部一致才计时有效",
             "", "| 库 | 文件数 | 告警数 | 串行(s) | 并行(s) | 加速比 | 结果一致 |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        lines.append(f"| {r['lib']} | {r['files']} | {r['issues']} | {r['serial_sec']} "
                     f"| {r['parallel_sec']} | ×{r['speedup']} | {'✓' if r['identical'] else '✗'} |")
    tot_f = sum(r["files"] for r in rows)
    tot_s = round(sum(r["serial_sec"] for r in rows), 2)
    tot_p = round(sum(r["parallel_sec"] for r in rows), 2)
    lines += ["", f"合计：{tot_f} 文件，串行 {tot_s}s → 并行 {tot_p}s"
              f"（总体 ×{round(tot_s / tot_p, 2) if tot_p else '—'}）", "",
              "> 口径：含规则库加载与文件 IO；并行按文件分片（chunksize=4），"
              "冻结态绿色版自动回退串行（窗口程序 spawn 风险）。", ""]
    out = ROOT / "docs" / "perf-scan-results.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    (ROOT / "out").mkdir(exist_ok=True)
    (ROOT / "out" / "perf_scan.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n结果 → {out}")
    return 0 if all(r["identical"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
