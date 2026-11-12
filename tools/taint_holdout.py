# -*- coding: utf-8 -*-
"""污点治理泛化性盲测：在六库之外的新仓库上跑治理后 TaintTracker，收集候选。

与 taint_eval.py 同口径，但目标换成 realtest-holdout/（jinja2/itsdangerous/
markupsafe）——这些库从未参与治理规则的设计与标注，用于检验四条通用规则
是否泛化（而非只在原六库自证）。候选附源码上下文供逐条盲核验。
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codeaudit import taint as TT                       # noqa: E402

HOLDOUT = ROOT.parent / "realtest-holdout"
LIBS = ["jinja2", "itsdangerous", "markupsafe"]


def main() -> int:
    rows = []
    for lib in LIBS:
        pkg = HOLDOUT / lib
        if not pkg.exists():
            print(f"[{lib}] 跳过：未找到（realtest-holdout/）")
            continue
        t0 = time.time()
        tt = TT.TaintTracker().build(pkg)
        seen = set()
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
            lo, hi = max(0, p["line"] - 7), min(len(lines), p["line"] + 6)
            ctx = "\n".join(f"{i + 1}| {lines[i]}" for i in range(lo, hi))
            rows.append({"lib": lib, "file": f.relative_to(pkg).as_posix(),
                         "line": p["line"], "call": p["call"], "cwe": p["cwe"],
                         "vars": p["vars"], "origin": p["origin"], "context": ctx})
        sinks = Counter(r["call"] for r in rows[n0:])
        print(f"[{lib}] 候选 {len(seen)} 条 stats={tt.stats()} "
              f"({time.time() - t0:.1f}s) sink={dict(sinks.most_common(8))}")
    out = ROOT / "out" / "taint_holdout_candidates.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n共 {len(rows)} 条候选 → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
