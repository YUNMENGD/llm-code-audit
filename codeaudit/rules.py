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


def _block_reraises(lines: list[str], idx: int) -> bool:
    """except 行（下标 idx）所属块体内是否重抛。

    对齐 bandit try_except_pass 语义：`except BaseException: cleanup(); raise`
    是资源清理+重抛的防御模式，不属于"吞异常"。判定：同行体内有 raise，
    或向下扫描同缩进块体的首个非注释语句即 raise。
    """
    row = lines[idx]
    colon = row.find(":")
    if colon >= 0 and re.search(r"\braise\b", row[colon + 1:]):
        return True
    base = len(row) - len(row.lstrip())
    for j in range(idx + 1, min(len(lines), idx + 40)):
        body = lines[j]
        if not body.strip() or body.lstrip().startswith("#"):
            continue
        indent = len(body) - len(body.lstrip())
        if indent <= base:
            break
        if re.match(r"raise(\s|$|from\b|,)", body.strip()):
            return True
    return False


def _docstring_mask(lines: list[str], source: str = "") -> list[bool]:
    """标记每行是否落在字符串字面量内部（docstring / 示例代码 / 日志文案）。

    首选 AST：真实解析所有 str 节点，覆盖任意引号形态与转义（行计数法会把
    r-string 末尾反斜杠、字符串里的 # 号等算错）；SyntaxError 时退回
    三引号奇偶计数兜底。仅屏蔽字符串的「中间行」——开闭行常与真代码
    同行混排，不整行排除，避免误挡真缺陷。
    """
    mask = [False] * len(lines)
    try:
        import ast as _ast
        tree = _ast.parse(source or "\n".join(lines))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Constant) and isinstance(node.value, str):
                if node.lineno is None or node.end_lineno is None:
                    continue
                if node.end_lineno > node.lineno:      # 多行串：屏蔽中间行
                    for j in range(node.lineno, node.end_lineno - 1):
                        if 0 <= j < len(mask):
                            mask[j] = True
        return mask
    except (SyntaxError, ValueError, MemoryError):
        pass
    in_str: str | None = None
    out: list[bool] = []
    for line in lines:
        code = line.split("#", 1)[0] if in_str is None else line
        out.append(in_str is not None)
        dq = code.count('"""')
        sq = code.count("'''")
        if in_str is None:
            if dq % 2 == 1:
                in_str = '"'
            elif sq % 2 == 1:
                in_str = "'"
        elif in_str == '"' and dq % 2 == 1:
            in_str = None
        elif in_str == "'" and sq % 2 == 1:
            in_str = None
    return out


def scan_source(source: str, rules: list[dict], path: str = "<inline>") -> list[Issue]:
    """对一段源码跑全部硬性规则，返回命中的 Issue 列表。"""
    lines = source.splitlines()
    doc = _docstring_mask(lines, source)
    hits: list[Issue] = []
    for r in rules:
        if not r.get("pattern"):
            continue
        try:
            rx = re.compile(r["pattern"])
        except re.error:
            continue
        skip_doc = r.get("skip_docstring", True)
        match_comment = r.get("match_comment", False)
        for i, ln in enumerate(lines):
            if skip_doc and doc[i]:
                continue
            if not match_comment and ln.lstrip().startswith("#"):
                continue
            if not rx.search(ln):
                continue
            if any(ex in ln for ex in r.get("exclude", [])):
                continue
            if r.get("body_check") == "no_reraise" and _block_reraises(lines, i):
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
