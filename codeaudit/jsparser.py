# -*- coding: utf-8 -*-
"""JS/TS 轻量函数切分（零第三方依赖，brace 匹配 + 字符串/注释/模板串状态机）。

定位：函数级审计需要把文件切成函数单元。不引 tree-sitter 重依赖，用状态机
跳过字符串/注释/模板串里的花括号，再按 brace 深度配对函数体——对常规
function 声明、箭头函数、类方法足够稳；解析失败的函数整文件兜底（宁粗勿漏）。

边界（诚实声明）：不做完整 AST，正则/装饰器/极端嵌套可能切偏；切偏时该函数
回退为文件级单元，不影响其余函数。这是试点期工程折中，AST 级精度留待后续。
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import CodeUnit

# 函数起点：function 名 / const|let|var 名 = (箭头或 function) / 类方法 名(...) {
_FUNC_RX = re.compile(
    r"(?:^|[;\n{}])\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
    r"|(?:^|[;\n{}])\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"
    r"|(?:^|[;\n{}])\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{")


def _mask_noncode(src: str) -> str:
    """把字符串/注释/模板串内容替换为等长空格（保留换行与花括号外的结构），
    使 brace 计数不被文案里的 {} 干扰。模板串 ${} 内的代码保留花括号。"""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "\"'":
            q = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    out[j] = " "
                    if j + 1 < n:
                        out[j + 1] = " "
                    j += 2
                    continue
                if src[j] == q:
                    break
                if src[j] != "\n":
                    out[j] = " "
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
            continue
        if c == "`":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "`":
                    break
                if src[j] == "$" and j + 1 < n and src[j + 1] == "{":
                    depth = 1
                    j += 2
                    while j < n and depth:
                        if src[j] == "{":
                            depth += 1
                        elif src[j] == "}":
                            depth -= 1
                        j += 1
                    continue
                if src[j] != "\n":
                    out[j] = " "
                j += 1
            i = j + 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i
            while j < n and src[j] != "\n":
                out[j] = " "
                j += 1
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = i + 2
            while j + 1 < n and not (src[j] == "*" and src[j + 1] == "/"):
                if src[j] != "\n":
                    out[j] = " "
                j += 1
            out[i] = out[i + 1] = " "
            if j + 1 < n:
                out[j] = out[j + 1] = " "
            i = j + 2
            continue
        i += 1
    return "".join(out)


def _match_body(masked: str, open_idx: int) -> int | None:
    """从 open_idx（'{' 位置）配对到闭合 '}'，返回闭合索引；失败 None。"""
    depth = 0
    for i in range(open_idx, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def split_js_functions(path: Path) -> list[CodeUnit]:
    """切出函数级单元；无函数或切分失败返回空列表（调用方回退文件级）。"""
    src = path.read_text(encoding="utf-8", errors="replace")
    masked = _mask_noncode(src)
    lines = src.splitlines()
    units: list[CodeUnit] = []
    spans: list[tuple[int, int]] = []
    for m in _FUNC_RX.finditer(masked):
        name = m.group(1) or m.group(2) or m.group(3)
        if not name or name in ("if", "for", "while", "switch", "catch", "return"):
            continue
        brace = masked.find("{", m.end() - 1)
        if brace < 0:
            continue
        close = _match_body(masked, brace)
        if close is None:
            continue
        # 行号从函数名实际位置算：正则前导 (?:^|[;\n{}]) 会吃掉上一函数闭合后
        # 的换行，用 m.start() 会把本函数起始行算到上一行造成重叠误判。
        # 注意未匹配组 m.start() 返回 -1（真值），不能用 or 短路，须按组号取
        g = 1 if m.group(1) else (2 if m.group(2) else 3)
        name_idx = m.start(g)
        start_line = src[:name_idx].count("\n") + 1
        end_line = src[:close].count("\n") + 1
        if end_line < start_line:
            continue                      # 行号倒挂（遮蔽器边界异常）→ 丢弃，宁粗勿坏
        if any(not (end_line < s or start_line > e) for s, e in spans):
            continue                      # 与已切函数重叠（嵌套）跳过，外层已含
        spans.append((start_line, end_line))
        body = "\n".join(lines[start_line - 1:end_line])
        units.append(CodeUnit(
            kind="function", name=name, path=str(path), source=body,
            line_start=start_line, line_end=end_line,
            context={"language": "JavaScript/TypeScript",
                     "functions": [name], "imports": []}))
    units.sort(key=lambda u: u.line_start)
    return units
