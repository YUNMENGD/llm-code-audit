# -*- coding: utf-8 -*-
"""JS/TS 静态规则层（多语言试点）：架构不变、弹药分库。

定位：证明分层降噪架构不绑死 Python——同一套「规则库 JSON + 扫描引擎 +
Issue 模型」换个语言弹药即可运转。试点用正则逐行匹配（与 Python 硬规则
同口径），不引入 tree-sitter 重依赖；AST 级精度留给后续迭代。

保守边界（与 Python 层同一纪律）：
- 行注释 // 与块注释 /* */ 内的文本不算命中（简易状态机遮蔽）；
- 字符串文案内的敏感词由规则自带 exclude 控制；
- # noqa / nosec 惯例映射为 // eslint-disable 与 // nosec 抑制标记；
- 语法不做解析，坏文件照常逐行扫（宁多报不漏报，裁决交上层）。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Category, Issue, Severity
from .paths import ROOT

JS_RULES_FILE = ROOT / "knowledge" / "rules" / "js_rules.json"
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_SUPPRESS_RX = re.compile(r"//\s*(eslint-disable|nosec|noqa)\b")
# 上一行的 disable-next-line 标记作用于下一行（ESLint 惯例）
_SUPPRESS_NEXT_RX = re.compile(r"//\s*eslint-disable-next-line\b")


def load_js_rules() -> list[dict]:
    try:
        data = json.loads(JS_RULES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data.get("rules", [])


def _comment_mask(lines: list[str]) -> list[bool]:
    """整行注释遮蔽：// 独立注释行与 /* */ 块内部行（开闭行不整行遮蔽）。"""
    mask = [False] * len(lines)
    in_block = False
    for i, ln in enumerate(lines):
        s = ln.strip()
        if in_block:
            mask[i] = True
            if "*/" in s:
                in_block = False
                # 闭行尾部若是代码则不遮蔽（保守：整行仍遮蔽，宁少报注释误报）
            continue
        if s.startswith("//"):
            mask[i] = True
        elif s.startswith("/*"):
            mask[i] = True
            if "*/" not in s[2:]:
                in_block = True
    return mask


def scan_js_source(source: str, rules: list[dict] | None = None,
                   path: str = "<inline>") -> list[Issue]:
    rules = rules if rules is not None else load_js_rules()
    lines = source.splitlines()
    mask = _comment_mask(lines)
    hits: list[Issue] = []
    for r in rules:
        try:
            rx = re.compile(r["pattern"])
        except (re.error, KeyError):
            continue
        exts = r.get("exts")
        if exts and Path(path).suffix.lower() not in exts:
            continue
        for i, ln in enumerate(lines):
            if mask[i]:
                continue
            # 行尾注释截断后再匹配（字符串内的 // 可能误截，保守可接受：
            # 截断只减少命中不增加命中，方向是降噪）
            code = ln.split("//", 1)[0]
            m = rx.search(code)
            if not m:
                continue
            if any(ex in ln for ex in r.get("exclude", [])):
                continue
            if _SUPPRESS_RX.search(ln):
                continue
            if i > 0 and _SUPPRESS_NEXT_RX.search(lines[i - 1]):
                continue
            hits.append(Issue(
                rule_id=r["id"],
                category=_cat(r.get("category", "security")),
                severity=_sev(r.get("severity", "medium")),
                title=r["title"],
                path=path,
                line_start=i + 1,
                evidence=ln.strip()[:200],
                analysis=r.get("why", ""),
                impact=r.get("impact", ""),
                fix=r.get("suggestion", ""),
                confidence=0.9,
                source=r.get("source", ""),
                detector="static",
                verified=True,
            ))
    return hits


def _sev(v: str) -> Severity:
    try:
        return Severity(str(v).lower())
    except ValueError:
        return Severity.MEDIUM


def _cat(v: str) -> Category:
    try:
        return Category(str(v).lower())
    except ValueError:
        return Category.SECURITY
