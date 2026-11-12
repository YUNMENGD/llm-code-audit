# -*- coding: utf-8 -*-
"""审计对比：两份报告按 (rule, path, line) 对齐，算新增 / 消除 / 存续。

用途：增量审计 + 回归验证闭环——治理前后、两次提交之间，问题集合的
变化必须可量化、可复核。行号漂移容忍：同 (rule, path) 且行距 ≤ drift
视为同一问题的移动（moved），不算新增+消除各一条。
"""
from __future__ import annotations

import json
from pathlib import Path


def _load(source) -> dict:
    """接受 dict / AuditReport / JSON 文件路径。"""
    if isinstance(source, dict):
        return source
    if hasattr(source, "to_json"):
        return json.loads(source.to_json())
    return json.loads(Path(source).read_text(encoding="utf-8"))


def _keys(doc: dict) -> dict[tuple, dict]:
    out = {}
    for it in doc.get("issues", []):
        k = (it.get("rule_id", ""), it.get("path", ""), int(it.get("line_start", 0)))
        out[k] = it
    return out


def diff_reports(old, new, drift: int = 3) -> dict:
    """返回 {added, removed, moved, kept, summary}。

    moved：同规则同文件、行号变化 ≤ drift 的配对（贪心最近匹配）。
    """
    a, b = _keys(_load(old)), _keys(_load(new))
    common = set(a) & set(b)
    only_a = set(a) - set(b)
    only_b = set(b) - set(a)

    moved: list[dict] = []
    # 贪心配对：按行距升序，一对一
    cands = sorted(
        (abs(ka[2] - kb[2]), ka, kb)
        for ka in only_a for kb in only_b
        if ka[0] == kb[0] and ka[1] == kb[1] and abs(ka[2] - kb[2]) <= drift)
    used_a: set = set()
    used_b: set = set()
    for d, ka, kb in cands:
        if ka in used_a or kb in used_b:
            continue
        used_a.add(ka)
        used_b.add(kb)
        moved.append({"rule": ka[0], "path": ka[1],
                      "old_line": ka[2], "new_line": kb[2],
                      "title": b[kb].get("title", "")})
    removed = [a[k] for k in sorted(only_a - used_a)]
    added = [b[k] for k in sorted(only_b - used_b)]
    kept = [b[k] for k in sorted(common)]
    return {
        "added": added, "removed": removed, "moved": moved, "kept": kept,
        "summary": {"old_total": len(a), "new_total": len(b),
                    "added": len(added), "removed": len(removed),
                    "moved": len(moved), "kept": len(kept)},
    }


def render_diff_markdown(d: dict, old_label: str = "旧", new_label: str = "新") -> str:
    s = d["summary"]
    lines = [f"# 审计对比：{old_label} → {new_label}", "",
             f"- 问题数：{s['old_total']} → {s['new_total']}",
             f"- 新增 **{s['added']}** · 消除 **{s['removed']}** · "
             f"行号移动 {s['moved']} · 存续 {s['kept']}", ""]
    if d["added"]:
        lines.append("## 新增问题")
        for it in d["added"]:
            lines.append(f"- [{it.get('severity', '?')}] {it.get('rule_id', '')} "
                         f"{Path(it.get('path', '')).name}:{it.get('line_start')} "
                         f"{it.get('title', '')}")
        lines.append("")
    if d["removed"]:
        lines.append("## 已消除问题")
        for it in d["removed"]:
            lines.append(f"- [{it.get('severity', '?')}] {it.get('rule_id', '')} "
                         f"{Path(it.get('path', '')).name}:{it.get('line_start')} "
                         f"{it.get('title', '')}")
        lines.append("")
    if d["moved"]:
        lines.append("## 行号移动（同一问题）")
        for m in d["moved"]:
            lines.append(f"- {m['rule']} {Path(m['path']).name}: "
                         f"{m['old_line']} → {m['new_line']}")
        lines.append("")
    return "\n".join(lines)
