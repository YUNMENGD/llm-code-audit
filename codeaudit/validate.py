"""结果校验：降低误报/漏报（对应申报书「审计结果验证与一致性」）。

三道闸门：
1. check_with_rules —— 定位与证据可回溯（行号存在、证据能在原文找到）
2. dedupe          —— 同规则同行合并，静态与模型同时命中则标记 both 并提升置信度
3. consistency_compare —— 多次运行结果比对，输出一致性指标（D15 方案的基础设施）
"""
from __future__ import annotations

from .models import Issue
from .rules import verify


def check_with_rules(issue: Issue, source_lines: list[str]) -> tuple[bool, str]:
    return verify(issue, source_lines)


def dedupe(issues: list[Issue]) -> list[Issue]:
    """按 (文件, 规则, 行) 合并；保留信息更丰富的一条，并累计 votes。"""
    merged: dict[tuple, Issue] = {}
    for it in issues:
        k = it.key()
        if k not in merged:
            merged[k] = it
            continue
        old = merged[k]
        keep, drop = (it, old) if _rank(it) >= _rank(old) else (old, it)
        keep.votes = old.votes + drop.votes
        if keep.detector != drop.detector:
            keep.detector = "both"
            keep.confidence = min(1.0, max(keep.confidence, drop.confidence) + 0.05)
        keep.line_end = keep.line_end or drop.line_end
        keep.impact = keep.impact or drop.impact
        merged[k] = keep
    return list(merged.values())


def consistency_compare(reports: list[list[Issue]]) -> dict:
    """多次运行的一致性：Jaccard 相似度 = 稳定命中数 / 出现过的规则数。

    返回 {"runs": n, "avg_pairwise": 0.xx, "stable_rules": [...]}
    avg_pairwise >= 0.8 视为稳定（申报书关键问题 4 的量化指标）。
    """
    n = len(reports)
    if n < 2:
        return {"runs": n, "avg_pairwise": 1.0 if n == 1 else 0.0,
                "stable_rules": sorted({i.rule_id for i in (reports[0] if reports else [])})}
    sets = [{(i.path, i.rule_id, i.line_start) for i in r} for r in reports]
    scores = []
    for a in range(n):
        for b in range(a + 1, n):
            u = sets[a] | sets[b]
            scores.append(len(sets[a] & sets[b]) / len(u) if u else 1.0)
    common = set.intersection(*sets) if sets else set()
    return {
        "runs": n,
        "avg_pairwise": round(sum(scores) / len(scores), 3) if scores else 0.0,
        "stable_rules": sorted({r[1] for r in common}),
    }


def _rank(i: Issue) -> tuple:
    return (i.verified, i.detector == "both", len(i.fix), i.confidence)
