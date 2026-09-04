"""硬性规则引擎：可程序校验的规则（不依赖 LLM，零误报底线）。

规则库位于 knowledge/rules/*.json，每条规则字段：
  id, title, severity, category, source, pattern(正则), exclude(可选,同行豁免词),
  cwe(可选), suggestion(修复建议), require_lines(可选,跳行匹配行数)

LLM 审计之外，本引擎先跑一遍并把命中的行号作为“线索”注入 Prompt（降低漏报），
LLM 结果再由 verify() 复核（降低误报）。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Category, Issue, Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "knowledge" / "rules"


def load_rules() -> list[dict]:
    rules: list[dict] = []
    if not RULES_DIR.exists():
        return rules
    for f in sorted(RULES_DIR.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        rules.extend(data.get("rules", []))
    return rules


def scan_source(source: str, rules: list[dict], path: str = "<inline>") -> list[Issue]:
    """对一段源码跑全部硬性规则，返回命中的 Issue 列表。"""
    lines = source.splitlines()
    hits: list[Issue] = []
    for r in rules:
        if not r.get("pattern"):
            continue
        try:
            rx = re.compile(r["pattern"])
        except re.error:
            continue
        for i, ln in enumerate(lines):
            if not rx.search(ln):
                continue
            if any(ex in ln for ex in r.get("exclude", [])):
                continue
            hits.append(Issue(
                rule_id=r["id"],
                category=_cat(r.get("category", "style")),
                severity=_sev(r.get("severity", "medium")),
                title=r["title"],
                path=path,
                line_start=i + 1,
                evidence=ln.strip()[:200],
                analysis=r.get("why", ""),
                impact=r.get("impact", ""),
                fix=r.get("suggestion", ""),
                confidence=0.95,           # 静态命中，置信度固定高
                source=r.get("source", ""),
                detector="static",
                verified=True,            # 硬性规则本身即校验
            ))
    return hits


def verify(issue: Issue, source_lines: list[str]) -> tuple[bool, str]:
    """校验 LLM 报告：定位行是否真实存在、证据是否能在原文找到。

    返回 (是否通过, 原因)。对应申报书「结果验证」要求的第一道闸门。
    """
    if not (1 <= issue.line_start <= len(source_lines)):
        return False, f"行号 {issue.line_start} 超出文件范围(1-{len(source_lines)})"
    if issue.evidence:
        joined = "\n".join(source_lines).replace(" ", "")
        if issue.evidence.replace(" ", "")[:40] not in joined:
            return False, "证据片段在原文中找不到，疑似模型幻觉"
    return True, "ok"


def _sev(v: str) -> Severity:
    try:
        return Severity(v.lower())
    except ValueError:
        return Severity.MEDIUM


def _cat(v: str) -> Category:
    try:
        return Category(v.lower())
    except ValueError:
        return Category.LOGIC
