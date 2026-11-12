# -*- coding: utf-8 -*-
"""高熵密钥检测（可选模块）：香农熵抓正则漏掉的凭据变体。

默认关闭（--entropy / AUDIT_ENTROPY=1）。启发式必然有噪声，因此：
- 置信度固定 0.6（低于硬规则的 0.95），报告里可一眼区分；
- 白名单排除路径/URL/带空格文案/纯十六进制摘要/占位符；
- 只在字符串字面量内取值，不扫代码结构；尊重 noqa/nosec 抑制标记。
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .models import Category, Issue, Severity

RULE_ID = "R-SEC-ENTROPY"
_STR_RX = re.compile(r"""(?<![\w])["'`]([^"'`\n]{16,200})["'`]""")
_HEX_RX = re.compile(r"^[0-9a-fA-F]+$")
_PLACEHOLDER_RX = re.compile(
    r"(?i)(example|placeholder|your[_-]?|xxxx|changeme|dummy|sample|test[_-]?key|<|\{\{|\$\{)")
_SUPPRESS_RX = re.compile(r"#\s*(noqa|nosec)\b|//\s*(eslint-disable|nosec)\b")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _looks_secret(s: str) -> bool:
    if len(s) < 20 or " " in s or "\t" in s:
        return False
    if _PLACEHOLDER_RX.search(s):
        return False
    if s.startswith(("http://", "https://", "/", "./", "../", "data:")):
        return False
    if "/" in s or "\\" in s:
        return False
    if _HEX_RX.match(s) and len(s) in (32, 40, 64):
        return False                      # MD5/SHA1/SHA256 摘要，非凭据
    has_alpha = any(c.isalpha() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return has_alpha and has_digit


def scan_source(source: str, path: str = "<inline>",
                min_entropy: float = 3.5) -> list:
    hits = []
    for i, ln in enumerate(source.splitlines(), 1):
        stripped = ln.strip()
        if stripped.startswith(("#", "//", "*")):
            continue
        if _SUPPRESS_RX.search(ln):
            continue
        for m in _STR_RX.finditer(ln):
            val = m.group(1)
            if not _looks_secret(val):
                continue
            ent = shannon(val)
            if ent < min_entropy:
                continue
            hits.append(Issue(
                rule_id=RULE_ID, category=Category.SECURITY,
                severity=Severity.HIGH,
                title="疑似高熵凭据字面量（熵 %.2f）" % ent,
                path=path, line_start=i, evidence=ln.strip()[:200],
                analysis="字符串长度 %d、香农熵 %.2f 超过阈值 %.2f，字符分布接近随机，"
                         "疑似真实密钥/令牌而非普通文案。" % (len(val), ent, min_entropy),
                impact="凭据随源码入库即泄露，历史提交同样可被检索。",
                fix="改为环境变量或密钥管理服务注入；已泄露的凭据立即轮换，"
                    "并用 gitleaks 清理历史提交。",
                confidence=0.6, source="Shannon entropy heuristic / CWE-798",
                detector="static", verified=True))
    return hits
