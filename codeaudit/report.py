"""报告生成：Markdown（人读）+ JSON（机读/复跑对比）。

输出结构对应申报书要求：问题分类整理、描述、风险分析、影响范围、
定位信息、修复建议，且每条带知识库来源（可解释、可溯源）。
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import AuditReport, Severity

_ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠",
         Severity.MEDIUM: "🟡", Severity.LOW: "🔵"}
_LABEL = {Severity.CRITICAL: "严重", Severity.HIGH: "高危",
          Severity.MEDIUM: "中危", Severity.LOW: "低危"}
_CAT = {"security": "安全漏洞", "logic": "逻辑错误",
        "style": "代码规范", "engineering": "工程实践"}


def render_markdown(r: AuditReport) -> str:
    s = r.stats
    lines = [
        "# 代码审计报告", "",
        f"- **审计对象**：`{r.target}`",
        f"- **审计引擎**：{r.engine.get('model', '?')}"
        f"（{'已调用大模型' if r.engine.get('llm_used') else '仅静态规则'}，"
        f"分析单元 {r.engine.get('units', 0)} 个，"
        f"知识库 {r.engine.get('knowledge_loaded', 0)} 条 / 规则 {r.engine.get('rules_loaded', 0)} 条）",
        f"- **结果概览**：共 **{s.get('total', 0)}** 个问题；"
        + "，".join(f"{_LABEL[Severity(k)] if k in [x.value for x in Severity] else k} {v}"
                    for k, v in (s.get("by_severity") or {}).items()) or "无",
        f"- **耗时**：{s.get('elapsed_sec', 0)} 秒", "",
    ]
    if not r.issues:
        lines += ["> ✅ 未发现问题。", ""]
        return "\n".join(lines)

    lines += ["## 问题清单", "",
              "| # | 级别 | 类别 | 规则 | 位置 | 问题 | 检出方式 |",
              "|---|---|---|---|---|---|---|"]
    for idx, i in enumerate(r.sorted_issues(), 1):
        loc = f"`{Path(i.path).name}:{i.line_start}`"
        det = {"static": "静态规则", "llm": "LLM", "both": "规则+LLM"}[i.detector]
        lines.append(f"| {idx} | {_ICON[i.severity]}{_LABEL[i.severity]} | {_CAT.get(i.category.value, i.category.value)} "
                     f"| {i.rule_id} | {loc} | {i.title} | {det} |")
    lines.append("")

    lines += ["## 详细说明", ""]
    for idx, i in enumerate(r.sorted_issues(), 1):
        rng = f"{i.line_start}-{i.line_end}" if i.line_end else f"{i.line_start}"
        lines += [
            f"### {idx}. {_ICON[i.severity]}{_LABEL[i.severity]}｜{i.title}", "",
            f"- **位置**：`{i.path}:{rng}`" + (f"（函数 `{i.function_name}`）" if i.function_name else ""),
            f"- **规则**：`{i.rule_id}`" + (f" ｜ 来源：{i.source}" if i.source else ""),
            f"- **检出**：{i.detector} ｜ 置信度 {i.confidence:.2f}"
            + (f" ｜ 命中 {i.votes} 次" if i.votes > 1 else ""),
            "",
            "```python",
            i.evidence or "# （模型未提供证据片段）",
            "```", "",
        ]
        if i.analysis:
            lines += [f"**分析**：{i.analysis}", ""]
        if i.impact:
            lines += [f"**影响**：{i.impact}", ""]
        if i.fix:
            lines += ["**修复建议**：", "", "```python" if "def " in i.fix or "= " in i.fix else "",
                      i.fix, "```" if "def " in i.fix or "= " in i.fix else "", ""]

    if s.get("by_category"):
        lines += ["## 分类统计", ""]
        for k, v in s["by_category"].items():
            lines.append(f"- {_CAT.get(k, k)}：{v}")
        lines.append("")
    return "\n".join(lines)


def write_report(r: AuditReport, out_md: str | Path,
                 out_json: str | Path | None = None) -> tuple[Path, Path | None]:
    out_md = Path(out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(r), encoding="utf-8")
    jp = None
    if out_json:
        jp = Path(out_json)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(r.to_json(), encoding="utf-8")
    return out_md, jp


def load_report_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
