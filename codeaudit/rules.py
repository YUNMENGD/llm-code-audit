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
GUARDS_FILE = RULES_DIR / "guards.json"


def load_guards() -> list[dict]:
    try:
        data = json.loads(GUARDS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data.get("guards", [])


def guard_coverage(source: str, guards: list[dict] | None = None) -> dict[str, set[int]]:
    """返回 {CWE/规则ID: 防护命中的行号集合}（文件级近似）。

    匹配 pattern 且（若有）requires 也命中 → 该行对 protects 中的 ID 构成防护点。
    抑制判定由 validate.guard_suppress 完成：告警行与防护点距离 ≤ window 才丢弃，
    避免"文件里有 safe_load 就把别处的真 pickle 漏洞也抑制"的漏报。
    """
    guards = guards if guards is not None else load_guards()
    lines = source.splitlines()
    covered: dict[str, set[int]] = {}
    for g in guards:
        try:
            rx = re.compile(g["pattern"])
            req = re.compile(g["requires"], re.I) if g.get("requires") else None
        except re.error:
            continue
        if req is not None and not req.search(source):
            continue
        for i, ln in enumerate(lines):
            if rx.search(ln):
                for c in g.get("protects", []):
                    covered.setdefault(c, set()).add(i + 1)
    return covered


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


def verify(issue: Issue, source_lines: list[str], *, window: int = 3) -> tuple[bool, str]:
    """校验 LLM 报告：证据必须出现在声明行号附近（±window），否则定位不可信。

    v0.3 评测（examples/bench）显示大量误报形态是"真代码 + 错行号"：
    模型把别处看到的 open/execute 挂到不相干的行上。只查全文存在放行这类报告，
    等于让审计结论的定位字段失去意义，故收紧为窗口匹配。
    """
    if not (1 <= issue.line_start <= len(source_lines)):
        return False, f"行号 {issue.line_start} 超出文件范围(1-{len(source_lines)})"
    if issue.evidence:
        ev = issue.evidence.replace(" ", "")[:40]
        if not ev:
            return True, "ok"
        lo = max(0, issue.line_start - 1 - window)
        hi = min(len(source_lines), (issue.line_end or issue.line_start) + window)
        win = "\n".join(source_lines[lo:hi]).replace(" ", "")
        if ev in win:
            return True, "ok"
        joined = "\n".join(source_lines).replace(" ", "")
        if ev in joined:
            return False, "证据在文件其他位置，行号定位漂移"
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
