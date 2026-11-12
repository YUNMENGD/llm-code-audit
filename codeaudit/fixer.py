# -*- coding: utf-8 -*-
"""一键修复：从审计发现的 fix 字段提取代码块，生成 diff 预览并可安全应用。

安全边界（宁可不修，不可修坏）：
- 只接受 fix 文本里的围栏代码块（```lang ... ```）作为替换候选；
- 证据锚定：issue.evidence 必须能在目标行附近唯一匹配，否则拒绝——
  防止模型建议落到错误的行上；
- 应用前自动备份 <file>.bak-<时间戳>；一次只改一个发现；
- 替换 = 用代码块整体替换证据所在行区间（line_start..line_end），
  保持原行首缩进基准（代码块若自带缩进则尊重原样）。
"""
from __future__ import annotations

import difflib
import re
import time
from pathlib import Path

_FENCE_RX = re.compile(r"```[a-zA-Z0-9_+\-]*\s*\n(.*?)```", re.S)


def extract_fix_code(fix_text: str) -> str | None:
    """取 fix 里第一个围栏代码块；无围栏返回 None（纯文字建议不可自动应用）。"""
    m = _FENCE_RX.search(fix_text or "")
    if not m:
        return None
    code = m.group(1).rstrip("\n")
    return code if code.strip() else None


def _anchor(lines: list[str], evidence: str, line_start: int,
            line_end: int | None) -> tuple[int, int] | None:
    """证据锚定：返回可替换的行区间（0 基，含端点），失败返回 None。"""
    ev = (evidence or "").strip()
    if not ev:
        return None
    end = (line_end or line_start)
    lo, hi = max(0, line_start - 1), min(len(lines), end)
    window = "\n".join(lines[lo:hi]).strip()
    ev_norm = re.sub(r"\s+", " ", ev)
    win_norm = re.sub(r"\s+", " ", window)
    if ev_norm and ev_norm in win_norm:
        return lo, hi - 1
    # 单行证据在 ±3 行内找唯一匹配
    if "\n" not in ev:
        cands = [i for i in range(max(0, line_start - 4),
                                  min(len(lines), line_start + 3))
                 if ev_norm in re.sub(r"\s+", " ", lines[i])]
        if len(cands) == 1:
            return cands[0], cands[0]
    return None


def preview(path: str | Path, issue: dict) -> dict:
    """生成 unified diff 预览。issue 为 Issue.to_dict() 形态。"""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "error": f"文件不存在：{p}"}
    code = extract_fix_code(issue.get("fix", ""))
    if code is None:
        return {"ok": False, "error": "修复建议中没有代码块，无法自动应用（请按文字建议手动修改）"}
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"读取失败：{e}"}
    lines = text.splitlines()
    span = _anchor(lines, issue.get("evidence", ""),
                   int(issue.get("line_start", 0)),
                   issue.get("line_end"))
    if span is None:
        return {"ok": False, "error": "证据无法在声明行附近唯一锚定，为安全起见拒绝自动修复"}
    lo, hi = span
    new_lines = lines[:lo] + code.splitlines() + lines[hi + 1:]
    diff = "\n".join(difflib.unified_diff(
        lines, new_lines, fromfile=str(p), tofile=str(p) + " (fixed)",
        lineterm=""))
    return {"ok": True, "diff": diff, "span": [lo + 1, hi + 1],
            "new_code": code}


def apply(path: str | Path, issue: dict) -> dict:
    """应用修复：先备份再写回。备份文件 <原名>.bak-<时间戳>。"""
    pv = preview(path, issue)
    if not pv["ok"]:
        return pv
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    lines = text.splitlines()
    lo, hi = pv["span"][0] - 1, pv["span"][1] - 1
    new_lines = lines[:lo] + pv["new_code"].splitlines() + lines[hi + 1:]
    backup = p.with_name(p.name + ".bak-" + time.strftime("%Y%m%d%H%M%S"))
    backup.write_text(text, encoding="utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    p.write_text(nl.join(new_lines) + (nl if text.endswith(("\n", "\r")) else ""),
                 encoding="utf-8")
    return {"ok": True, "backup": str(backup), "diff": pv["diff"]}
