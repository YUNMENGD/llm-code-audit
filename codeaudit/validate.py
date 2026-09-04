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


def _norm_key(rule_id: str, amap: dict[str, str]) -> str:
    """rule_id → 合并键：映射表优先；DISCOVERED-CWE-x-NN 提取其中的 CWE-x。

    双模型常对同一问题给出不同表述（qwen 给 CWE-95、deepseek 给
    DISCOVERED-CWE-95-02），不归一则永远合不上。
    """
    if rule_id in amap:
        return amap[rule_id]
    import re as _re
    m = _re.match(r"DISCOVERED-(CWE-\d+)", rule_id)
    if m:
        return m.group(1)
    return rule_id


def cross_review(issues: list[Issue], *, enabled: bool,
                 n_models: int = 2) -> dict:
    """D15 双模型交叉复核：按实际来源模型数 len(models) 判定共识。

    - static：仅规则命中，不计入模型投票。
    - models >= 2：≥2 个模型报告同点 = 共识（detector=both/cross 均算）。
    - detector=both 且单模型：有规则背书，计入 confirmed_by_rule，不算孤证。
    - llm/cross 且单模型：孤证，标注「待人工确认」保留（宁审勿漏）。
    返回统计供论文实验：agreement_rate = 共识 / (共识 + 孤证)。
    """
    if not enabled or n_models < 2:
        return {"enabled": False}
    agreed = single = by_rule = 0
    for it in issues:
        if it.detector == "static":
            continue
        if len(it.models) >= 2:
            agreed += 1
        elif it.detector == "both":
            by_rule += 1                 # 单模型+规则背书，不标孤证
        else:
            single += 1
            if not it.analysis.startswith(REVIEW_MARK):
                it.analysis = (REVIEW_MARK + f"[双模型交叉复核：仅 {it.models or ['?']} 报告，"
                               f"另一模型未见同点问题] " + it.analysis)
    total = agreed + single
    return {"enabled": True, "models": n_models, "agreed": agreed,
            "single_model": single, "confirmed_by_rule": by_rule,
            "agreement_rate": round(agreed / total, 3) if total else None}


def guard_suppress(issues: list[Issue], cov_map: dict[str, dict[str, set[int]]],
                   *, window: int = 3) -> tuple[list[Issue], list[str]]:
    """抑制「API 名匹配但防护已到位」的 LLM 误报。

    cov_map: 文件路径 → {CWE/规则ID: 防护点行号集合}（按文件隔离，防跨文件串位）。
    仅作用于 llm 单源告警（static/both 有规则背书不抑制）；
    告警行与同文件防护点距离 ≤ window 才抑制——离防护代码那么近还报，
    大概率就是白名单误报（neg03 里 safe_load 被报 CWE-502 的形态）。
    返回 (保留的告警, 被抑制说明列表)。
    """
    if not cov_map:
        return issues, []
    amap = _load_map()
    kept: list[Issue] = []
    suppressed: list[str] = []
    for it in issues:
        if it.detector != "llm":
            kept.append(it)
            continue
        cov = cov_map.get(it.path) or {}
        key = _norm_key(it.rule_id, amap)
        pts = cov.get(key)
        if pts:
            lo = it.line_start
            hi = it.line_end or lo
            near = [p for p in pts if lo - window <= p <= hi + window]
            if near:
                suppressed.append(
                    f"{Path(it.path).name}:{lo} {it.rule_id} ← 防护点 L{near[0]} ({key})")
                continue
        kept.append(it)
    return kept, suppressed


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
        key = _norm_key(it.rule_id, amap)
        for exist in out:
            ek = _norm_key(exist.rule_id, amap)
            if ek != key or exist.path != it.path:
                continue
            same_src = exist.detector == it.detector
            # 同 detector 仅在「都是 llm 且来自不同模型」时才合并（双模型投票）
            both_llm = exist.detector == "llm" and it.detector == "llm"
            diff_model = bool(set(exist.models) and set(it.models)
                              and not (set(exist.models) & set(it.models)))
            if same_src and not (both_llm and diff_model):
                continue
            if _overlap(exist, it):
                target = exist
                break
        if target is None:
            out.append(it)
            continue
        rich, poor = (it, target) if len(it.analysis) >= len(target.analysis) else (target, it)
        merged_models = sorted(set(rich.models) | set(poor.models))
        if rich.detector == poor.detector == "llm":
            rich.detector = "cross"
        elif rich.detector != poor.detector:
            rich.detector = "both"
        rich.models = merged_models
        rich.votes = rich.votes + poor.votes
        rich.verified = it.verified or target.verified
        rich.confidence = min(1.0, max(it.confidence, target.confidence))
        rich.source = rich.source or poor.source
        rich.line_start = min(rich.line_start, poor.line_start)
        rich.line_end = max(rich.line_end or rich.line_start, poor.line_end or poor.line_start)
        out = [x for x in out if x is not target and x is not poor]
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
        keep.models = sorted(set(old.models) | set(drop.models))
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
