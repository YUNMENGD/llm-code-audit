# -*- coding: utf-8 -*-
"""知识库评审门禁：custom 变更的机器预审 + bench-real 静态回归红线。

用途：知识库众包评审流的第一道闸——PR 里改了 knowledge/ 的自定义条目/
规则，CI 先跑本脚本；机器只把「格式坏、来源缺、正则非法、误杀真缺陷」
拦下来，语义质量仍由人工评审裁决（与数据飞轮纪律一致）。

检查项：
1. custom.json / custom_rules.json schema：必填字段、枚举取值、ID 规范；
2. 每条知识条目必须带 source（可溯源纪律）；每条规则正则必须可编译；
3. ID 不得与内置条目/规则冲突（内置只读保护）；
4. bench-real 静态回归：六库真缺陷（verdict=T）零误杀——任何自定义
   规则/豁免导致 T 告警消失即 FAIL（红线）。

用法：python tools/kb_review.py   （退出码 0=过 / 1=拦）
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codeaudit import kbadmin as KA                    # noqa: E402
from codeaudit import realeval as RE                   # noqa: E402

_SEVS = {"critical", "high", "medium", "low"}
_CATS = {"security", "logic", "style", "engineering"}
_ID_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{1,63}$")


def check_schema() -> list[str]:
    errs: list[str] = []
    builtin_kb = {it["id"] for it in KA.list_items() if it["_builtin"]}
    builtin_rl = {r["id"] for r in KA.list_rules() if r["_builtin"]}
    for it in KA.list_items():
        if it["_builtin"]:
            continue
        iid = it.get("id", "")
        if not _ID_RX.match(iid):
            errs.append(f"知识条目 ID 非法：{iid!r}")
        if iid in builtin_kb:
            errs.append(f"自定义条目与内置冲突：{iid}")
        if not str(it.get("title", "")).strip():
            errs.append(f"{iid}: 缺标题")
        if it.get("severity") not in _SEVS:
            errs.append(f"{iid}: 严重度非法 {it.get('severity')!r}")
        if it.get("category") not in _CATS:
            errs.append(f"{iid}: 类别非法 {it.get('category')!r}")
        if not str(it.get("source", "")).strip():
            errs.append(f"{iid}: 缺来源（可溯源纪律：新增必须带 source）")
    for r in KA.list_rules():
        if r["_builtin"]:
            continue
        rid = r.get("id", "")
        if not _ID_RX.match(rid):
            errs.append(f"规则 ID 非法：{rid!r}")
        if rid in builtin_rl:
            errs.append(f"自定义规则与内置冲突：{rid}")
        if not str(r.get("title", "")).strip():
            errs.append(f"{rid}: 缺标题")
        try:
            re.compile(r.get("pattern", ""))
        except re.error as e:
            errs.append(f"{rid}: 正则非法 {e}")
        if not str(r.get("source", "")).strip():
            errs.append(f"{rid}: 缺来源")
    return errs


def check_regression() -> list[str]:
    """bench-real 静态回归：真缺陷零误杀红线。"""
    errs: list[str] = []
    for lib in RE.LIBS:
        r = RE.evaluate(lib)
        if "error" in r:
            print(f"  [skip] {lib}: {r['error']}")
            continue
        lost = r["current"]["lost_T"]
        kept = r["current"]["kept_T"]
        total = r["baseline"]["T"]
        print(f"  {lib}: 真缺陷保留 {kept}/{total}（误杀 {lost}）")
        if lost:
            errs.append(f"{lib}: {lost} 条真缺陷被误杀——违反零误杀红线")
    return errs


def main() -> int:
    print("[1] schema / 来源 / 正则 / ID 冲突")
    errs = check_schema()
    for e in errs:
        print("  ✗", e)
    if not errs:
        print("  ✓ 全部通过")
    print("[2] bench-real 静态回归（零误杀红线）")
    errs += check_regression()
    if errs:
        print(f"\nREVIEW_FAIL：{len(errs)} 项拦截")
        return 1
    print("\nREVIEW_PASS：机器预审通过，语义质量请人工评审")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
