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
from .paths import RULES_DIR as _RD

RULES_DIR = _RD
GUARDS_FILE = RULES_DIR / "guards.json"

# 通用抑制惯例（bandit/ruff/pylint 生态共识）：作者显式标记"我知道，故意的"。
# 注意不含 type: ignore——那是类型系统标记，不表达安全/资源语义豁免。
_SUPPRESS_RX = re.compile(r"#\s*(noqa|nosec|pylint:\s*disable)\b")


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


_PROBE_STMT = re.compile(
    r"^(continue|return\s+(False|True|None|default|-?\d+|[\"'][^\"']*[\"'])\s*$"
    r"|return\s*$|\w+\s*=\s*(None|False|True|\[\]|\{\}|[\"'][^\"']*[\"']?)\s*(#.*)?$)")
# 注意：pass 不在豁免内——"异常处理不当"是申报书明确的研究目标缺陷类，
# 静默吞掉必须保留报警；确属故意的（如 __del__ 清理）作者应显式 # noqa 表明意图。


def _except_probe(lines: list[str], idx: int) -> bool:
    """探测惯用法（模式F1）：显式 except Exception 且块体是降级返回/兜底赋值。

    能力探测范式 `try: 试操作 / except Exception: return False` 是 CLI/IO 库的
    合法写法。保守边界：裸 except 与 BaseException 不豁免；块体含 pass/raise
    或赋值/调用等实质逻辑不豁免；嵌套 try 探测（体以 try: 开头）不覆盖——
    宁可留报不误删真缺陷。
    """
    row = lines[idx].strip()
    if not re.match(r"except\s+Exception(\s+as\s+\w+)?\s*:\s*(#.*)?$", row):
        return False
    base = len(lines[idx]) - len(lines[idx].lstrip())
    body: list[str] = []
    for j in range(idx + 1, min(len(lines), idx + 8)):
        b = lines[j]
        if not b.strip() or b.lstrip().startswith("#"):
            continue
        if len(b) - len(b.lstrip()) <= base:
            break
        body.append(b.strip())
    if not body:
        return False
    for stmt in body:
        if stmt.startswith(("raise", "try", "if", "for", "while", "with")):
            return False
        if not _PROBE_STMT.match(stmt):
            return False
    return True


_VAR_ASSIGN = re.compile(r"^\s*(\w+)\s*=\s*(?:[^\n]*\b(?:open|connect)\s*\()")


_LOG_CALL = re.compile(
    r"\b(?:logger|logging|log|self\.log)\s*\.\s*(?:debug|info|warning|warn|error|exception|critical)\s*\("
    r"|\b[A-Z][A-Z0-9_]*_?LOGGER\b\s*\.\s*\w+\s*\("   # trio 惯例：ASYNCGEN_LOGGER.exception(...)
    r"|\bwarnings\s*\.\s*warn(?:ing)?\s*\("
    r"|\btraceback\s*\.\s*print"
    r"|\.showtraceback\s*\("
    r"|exc_info\s*=\s*True")


def _except_logged(lines: list[str], idx: int) -> bool:
    """记录型宽捕获（模式扩展·logged-degrade）：except 块体内记录了异常即非"吞掉"。

    R-LOG-001 的语义是"吞"——故障不可见。`except Exception: logger.debug(..., exc_info=True)`
    与 `self.showtraceback()` 是"捕获+上报+降级继续"，可见性未破坏，属合法工程惯用法
    （botocore endpoint/history、werkzeug debug console 实证）。块体只有 pass 不属于此类——
    静默吞掉是申报书目标缺陷类，保留报警，故意者请 # noqa 声明意图。
    """
    row = lines[idx].strip()
    if not re.match(r"except\s+(:|Exception|BaseException)(\s+as\s+\w+)?\s*:", row):
        return False
    base = len(lines[idx]) - len(lines[idx].lstrip())
    for j in range(idx + 1, min(len(lines), idx + 12)):
        b = lines[j]
        if not b.strip():
            continue
        if len(b) - len(b.lstrip()) <= base:
            break
        if _LOG_CALL.search(b):
            return True
    return False


def _resource_managed(lines: list[str], idx: int) -> bool:
    """finally/下游接管（模式扩展）：赋值行下方窗口出现同名 .close() 即豁免。

    click _termui_impl 实证：null=open(...)+finally null.close()、
    f=open(...)+if f is not None: f.close() 都是正确生命周期管理。
    残余风险（部分路径漏关）为启发式已知边界，交由 LLM 层复核；
    作者真在意的误报可用 # noqa 显式豁免（已支持）。
    """
    m = _VAR_ASSIGN.match(lines[idx])
    if not m:
        return False
    var = m.group(1)
    rx = re.compile(rf"\b{re.escape(var)}\.close\s*\(")
    for j in range(idx + 1, min(len(lines), idx + 40)):
        if rx.search(lines[j]):
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


def _paren_depths(source: str) -> dict[int, int]:
    """行号 → 该行首 token 出现时的括号嵌套深度。

    E731 只约束顶层 `f = lambda`；`foo(kw=lambda: ...)` 换行后行首同样是
    kw=lambda 形态，靠深度>0 区分——botocore/werkzeug/flask/click 实证误报。
    tokenize 失败返回 {}（视为全在顶层，宁报不误删）。
    """
    import io
    import tokenize
    depths: dict[int, int] = {}
    depth = 0
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
                            tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER):
                continue
            if tok.start[0] not in depths:
                depths[tok.start[0]] = depth       # 行首深度 = 该 token 前累计
            if tok.type == tokenize.OP:
                if tok.string in "([{":
                    depth += 1
                elif tok.string in ")]}":
                    depth = max(0, depth - 1)
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return {}
    return depths


def _comment_cols(source: str) -> dict[int, int]:
    """行号 → 该行行内注释（COMMENT token）的起始列。

    模式 COMMENT：命中位置落在 `#` 之后即注释文本，不是代码。trio 实证——
    `for _tick in range(5):  # expected need is 2 iterations` 的行尾注释里的
    "is 2" 误撞 R-LOG-003 的 `is <数字>` 模式。tokenize 把整行注释（含独立
    注释行与行尾注释）都标为 COMMENT token；独立注释行上游已跳过，这里
    主要消费行尾注释。tokenize 失败返回 {}（视为无注释，宁可多报不误删）。
    """
    import io
    import tokenize
    cols: dict[int, int] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                cols[tok.start[0]] = tok.start[1]
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return {}
    return cols


def _string_spans(source: str) -> dict[int, list[tuple[int, int]]]:
    """行号 → 字符串文本 token 覆盖的列区间（模式 E：字符串内的敏感词）。

    收集 STRING 与 FSTRING_MIDDLE（3.12+ f-string 的字面文本段）两类 token——
    即"人读的文案区"。f-string 表达式 `{...}` 内部是真实代码，不遮蔽，方向保守。
    多行串逐行展开。tokenize 失败返回 {}（视为无遮蔽，宁可多报不误删）。
    """
    import io
    import tokenize
    spans: dict[int, list[tuple[int, int]]] = {}
    text_types = {tokenize.STRING}
    for name in ("FSTRING_MIDDLE",):
        t = getattr(tokenize, name, None)
        if t is not None:
            text_types.add(t)
    try:
        lines = source.splitlines()
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type not in text_types:
                continue
            (sr, sc), (er, ec) = tok.start, tok.end
            if sr == er:
                spans.setdefault(sr, []).append((sc, ec))
            else:
                if 0 < sr <= len(lines):
                    spans.setdefault(sr, []).append((sc, len(lines[sr - 1])))
                for r in range(sr + 1, er):
                    if 0 < r <= len(lines):
                        spans.setdefault(r, []).append((0, len(lines[r - 1])))
                if 0 < er <= len(lines):
                    spans.setdefault(er, []).append((0, ec))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return {}
    return spans


def scan_source(source: str, rules: list[dict], path: str = "<inline>") -> list[Issue]:
    """对一段源码跑全部硬性规则，返回命中的 Issue 列表。"""
    lines = source.splitlines()
    doc = _docstring_mask(lines, source)
    strspans = _string_spans(source)     # 模式E：字符串文案内的敏感词不算命中
    cmts = _comment_cols(source)         # 模式COMMENT：行尾注释文本非代码
    depths = _paren_depths(source) if any(r.get("top_only") for r in rules) else {}
    hits: list[Issue] = []
    for r in rules:
        if not r.get("pattern"):
            continue
        try:
            rx = re.compile(r["pattern"])
        except re.error:
            continue
        skip_path = r.get("skip_path_rx")
        if skip_path:
            try:
                if re.search(skip_path, path.replace("\\", "/")):
                    continue         # 规则级路径豁免（如 vendored 第三方代码）
            except re.error:
                pass
        skip_doc = r.get("skip_docstring", True)
        match_comment = r.get("match_comment", False)
        for i, ln in enumerate(lines):
            if skip_doc and doc[i]:
                continue
            if not match_comment and ln.lstrip().startswith("#"):
                continue
            m = rx.search(ln)
            if not m:
                continue
            if any(a <= m.start() < b for a, b in strspans.get(i + 1, ())):
                continue                 # 匹配起点在字符串文本内 → 文案非代码
            if not match_comment and i + 1 in cmts and m.start() >= cmts[i + 1]:
                continue                 # 模式COMMENT：命中在行尾注释里 → 文本非代码
            if r.get("top_only") and depths.get(i + 1, 0) > 0:
                continue                 # 跨行调用括号内的参数行不算顶层语句（E731 实证）
            if any(ex in ln for ex in r.get("exclude", [])):
                continue
            if _SUPPRESS_RX.search(ln):
                continue                 # 作者显式抑制标记（ruff/bandit/pylint 惯例）
            if r.get("body_check") == "no_reraise" and _block_reraises(lines, i):
                continue
            if r.get("probe_check") == "except_probe" and _except_probe(lines, i):
                continue                 # 模式F1：能力探测降级返回
            if r.get("logged_check") == "except_logged" and _except_logged(lines, i):
                continue                 # 模式logged-degrade：块体已记录异常，非"吞掉"
            if r.get("resource_check") == "managed" and _resource_managed(lines, i):
                continue                 # finally/下游已接管关闭
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
