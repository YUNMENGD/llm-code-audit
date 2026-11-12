# -*- coding: utf-8 -*-
"""静态扫描并行化：进程池按文件分片，结果与串行逐条一致。

设计：
- 规则库在主进程加载一次，随任务传引用（fork）或子进程自加载（spawn），
  worker 只做「读文件 → scan_source/scan_js_source」纯函数计算；
- 结果按文件序合并后再按 (path, rule_id, line) 排序，与串行输出完全一致
  （评测口径不因并行漂移）；
- 单文件失败容错跳过并计数，不拉闸整批；
- 冻结态（PyInstaller）默认回退串行：窗口程序 spawn 子进程会重跑入口，
  风险大于收益；源码态 CLI/服务端可放心用。
"""
from __future__ import annotations

import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


def _scan_one(args: tuple[str, str]) -> tuple[str, list[dict] | None]:
    """子进程任务：返回 (path, issues_dicts)；读失败返回 (path, None)。"""
    path, lang = args
    try:
        src = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return path, None
    if lang == "js":
        from . import jsrules as JR
        issues = JR.scan_js_source(src, JR.load_js_rules(), path)
    else:
        from . import rules as RL
        issues = RL.scan_source(src, RL.load_rules(), path)
    return path, [i.to_dict() for i in issues]


def default_workers(n_files: int) -> int:
    if getattr(sys, "frozen", False):
        return 1                      # 冻结态回退串行（见模块 docstring）
    if n_files < 64:
        # 实测阈值：Windows spawn 开销下小目录并行负优化
        # （17~53 文件 ×0.44~0.95），≥64 才回本（trio ×2.04）
        return 1
    cpu = os.cpu_count() or 4
    return max(2, min(cpu - 1, 8, n_files))


def scan_files_parallel(files: list[Path], workers: int | None = None,
                        ) -> tuple[list, int]:
    """并行扫描，返回 (Issue 列表按稳定序, 跳过文件数)。

    workers=1 或文件数 <8 时直接串行（进程池开销不划算）。
    """
    from . import jsrules as JR
    from .models import Issue

    tasks = [(str(f), "js" if f.suffix in JR.JS_EXTS else "py") for f in files]
    w = workers if workers is not None else default_workers(len(tasks))
    results: list[tuple[str, list[dict] | None]] = []
    if w <= 1 or len(tasks) < 8:
        results = [_scan_one(t) for t in tasks]
    else:
        with ProcessPoolExecutor(max_workers=w) as pool:
            results = list(pool.map(_scan_one, tasks, chunksize=4))
    issues: list[Issue] = []
    skipped = 0
    for path, rows in results:
        if rows is None:
            skipped += 1
            continue
        for d in rows:
            it = Issue.from_dict(d, path=d.get("path", path),
                                 detector=d.get("detector", "static"))
            it.verified = bool(d.get("verified", True))
            it.confidence = float(d.get("confidence", 0.95))
            issues.append(it)
    issues.sort(key=lambda i: (i.path, i.rule_id, i.line_start))
    return issues, skipped
