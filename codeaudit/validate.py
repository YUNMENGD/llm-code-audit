"""结果校验：降低误报/漏报（对应申报书「审计结果验证与一致性」）。

三道闸门：
1. check_with_rules —— 定位与证据可回溯（行号存在、证据能在原文找到）
2. dedupe          —— 同规则同行合并，静态与模型同时命中则标记 both 并提升置信度
3. consistency_compare —— 多次运行结果比对，输出一致性指标（D15 方案的基础设施）
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Issue, Severity
from .rules import verify

_MAP_FILE = (Path(__file__).resolve().parent.parent
             / "knowledge" / "rules" / "cwe_map.json")

REVIEW_MARK = "⚠️待人工确认："
DISCOVERED_PREFIX = "DISCOVERED"


def check_with_rules(issue: Issue, source_lines: list[str]) -> tuple[bool, str]:
    return verify(issue, source_lines)


def rule_id_gate(issues: list[Issue], valid_ids: set[str]) -> list[Issue]:
    """白名单闸门：LLM 报告的 rule_id 必须真实存在于知识库/规则库。

    试跑 v0.2 发现模型会把 eval 的 ID 错写成 CWE-502（应为 CWE-95），
    错 ID 会污染溯源链。处理策略：
    - DISCOVERED-*（模型自编号）与已在库的 ID → 放行
    - 其余未知 ID → 降级为 DISCOVERED-<原ID>，并在 analysis 标注，保留问题不丢
    """
    if not valid_ids:
        return issues
    seq = 0
    for it in issues:
        if it.detector == "static":
            continue
        rid = it.rule_id.strip()
        if rid in valid_ids or rid.startswith(DISCOVERED_PREFIX):
            continue
        seq += 1
        it.analysis = f"[rule_id 已纠正：模型给出 {rid} 不在知识库] " + it.analysis
        it.rule_id = f"DISCOVERED-{rid}-{seq:02d}"
    return issues


def confidence_gate(issues: list[Issue], drop: float = 0.5,
                    review: float = 0.7) -> list[Issue]:
    """T2 闸门：LLM 单源且置信度过低的丢弃；0.5~0.7 的标注待人工确认。

    静态命中（detector=static/both）不受此闸门影响（置信度由规则本身保证）。
    """
    kept: list[Issue] = []
    for it in issues:
        if it.detector == "llm" and it.confidence < drop:
            continue                      # 丢弃，stats 里计入 dropped
        if it.detector == "llm" and it.confidence < review:
            if not it.analysis.startswith(REVIEW_MARK):
                it.analysis = REVIEW_MARK + it.analysis
        kept.append(it)
    return kept


def cwe_merge(issues: list[Issue]) -> list[Issue]:
    """T3 合并：静态规则与 LLM 命中同一 CWE、行号区间重叠时并为一条。

    保留 LLM 的富文本（analysis/fix），继承静态的 verified 与更高置信度，
    detector 标 both，votes 累加。需要 knowledge/rules/cwe_map.json。
    """
    amap = _load_map()
    out: list[Issue] = []
    for it in issues:
        target = None
        key = amap.get(it.rule_id, it.rule_id)
        for exist in out:
            ek = amap.get(exist.rule_id, exist.rule_id)
            if ek != key or exist.path != it.path or exist.detector == it.detector:
                continue
            if _overlap(exist, it):
                target = exist
                break
        if target is None:
            out.append(it)
            continue
        rich, poor = (it, target) if len(it.analysis) >= len(target.analysis) else (target, it)
        rich.detector = "both"
        rich.verified = it.verified or target.verified
        rich.votes = it.votes + target.votes
        rich.confidence = min(1.0, max(it.confidence, target.confidence))
        rich.source = rich.source or poor.source
        rich.line_start = min(rich.line_start, poor.line_start)
        rich.line_end = max(rich.line_end or rich.line_start, poor.line_end or poor.line_start)
        out.remove(poor)
        out.append(rich)
    return out


def _load_map() -> dict[str, str]:
    try:
        return json.loads(_MAP_FILE.read_text(encoding="utf-8")).get("map", {})
    except (OSError, json.JSONDecodeError):
        return {}


def _overlap(a: Issue, b: Issue) -> bool:
    ae = a.line_end or a.line_start
    be = b.line_end or b.line_start
    return a.line_start <= be and b.line_start <= ae



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
