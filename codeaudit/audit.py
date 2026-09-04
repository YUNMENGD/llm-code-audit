"""审计工作流编排：多粒度（工程级→文件级→函数级）+ RAG + 结果校验。

流程（对应申报书实施方案 6~7 条）：
1. 静态硬性规则先扫一遍 → 得到线索行号
2. 检索知识库 → 组装 Prompt（代码 + 行号 + 知识 + 线索）
3. 调用 LLM 输出 JSON 问题列表
4. 校验器复核（行号真实性、证据可回溯、置信度阈值）
5. 合并静态结果与模型结果，按位置去重
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from . import parser as P
from . import retriever as R
from . import rules as RL
from . import validate as V
from .llm import LLMClient, LLMError, extract_json_array
from .models import AuditReport, CodeUnit, Issue

PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts"


def load_prompt(name: str) -> str:
    f = PROMPT_DIR / name
    return f.read_text(encoding="utf-8") if f.exists() else ""


def audit_path(target: str | Path, depth: str = "file") -> AuditReport:
    """审计一个文件或目录。depth: function(逐函数) | file(整体) | project(工程级)"""
    target = Path(target)
    started = time.time()
    client = LLMClient()
    static_rules = RL.load_rules()
    knowledge = R.load_knowledge()
    issues: list[Issue] = []
    engine = {"model": client.model if client.available() else "static-only",
              "depth": depth, "llm_used": False, "units": 0}

    files = [target] if target.is_file() else sorted(
        p for p in target.rglob("*.py")
        if not any(part in P.IGNORE_DIRS for part in p.parts))

    for f in files:
        file_unit = P.parse_file(f)
        source_lines = file_unit.source.splitlines()

        # ① 静态硬性规则
        issues += RL.scan_source(file_unit.source, static_rules, str(f))

        # ② LLM 审计（未配置密钥则跳过，系统仍可输出静态结果）
        if client.available():
            engine["llm_used"] = True
            units: list[CodeUnit] = []
            if depth == "function":
                units = P.split_functions(file_unit) or [file_unit]
            elif depth == "project" and target.is_dir():
                units = [P.parse_project(target)]
            else:
                units = [file_unit]
            for u in units:
                engine["units"] += 1
                issues += _audit_unit(client, u, source_lines, static_rules, knowledge)

    # ③ 校验 + 去重
    issues = V.dedupe(issues)
    issues = [i for i in issues if not (i.detector == "llm" and not i.verified)]
    consistency_runs = int(os.getenv("AUDIT_CONSISTENCY_RUNS", "1"))

    report = AuditReport(
        target=str(target),
        issues=issues,
        engine={**engine, "consistency_runs": consistency_runs,
                "knowledge_loaded": len(knowledge), "rules_loaded": len(static_rules)},
    )
    report.stats = {
        "total": len(issues),
        "by_severity": report.count_by("severity"),
        "by_category": report.count_by("category"),
        "by_detector": report.count_by("detector"),
        "elapsed_sec": round(time.time() - started, 2),
    }
    return report


def _audit_unit(client: LLMClient, unit: CodeUnit, source_lines: list[str],
                static_rules: list[dict], knowledge: list[dict]) -> list[Issue]:
    """单个工作单元的 LLM 审计：检索知识 → 组 Prompt → 调用 → 解析 → 校验。"""
    hints = RL.scan_source(unit.source, static_rules, unit.path)
    query = unit.source[:3000] + " " + " ".join(unit.context.get("imports", []))
    hits = R.retrieve(query, top_k=5, items=knowledge)

    tpl = load_prompt(f"{unit.kind}_audit.md") or load_prompt("file_audit.md")
    prompt = (tpl
              .replace("{{language}}", "Python")
              .replace("{{scope}}", f"{unit.kind}: {unit.name}")
              .replace("{{context}}", _context_block(unit))
              .replace("{{knowledge}}", R.format_for_prompt(hits))
              .replace("{{hints}}", _hints_block(hints))
              .replace("{{code}}", unit.tagged()))

    messages = [
        {"role": "system", "content": "你是资深代码审计专家，只输出符合要求的 JSON，不输出任何解释文字。"},
        {"role": "user", "content": prompt},
    ]
    try:
        raw = client.chat(messages)
    except LLMError as e:
        print(f"[warn] 模型调用失败({unit.path}): {e}")
        return []

    out: list[Issue] = []
    for item in extract_json_array(raw):
        if not isinstance(item, dict):
            continue
        issue = Issue.from_dict(item, path=unit.path, detector="llm")
        ok, reason = V.check_with_rules(issue, source_lines)
        issue.verified = ok
        if not ok:
            issue.analysis = f"[校验未通过:{reason}] {issue.analysis}"
        out.append(issue)
    return out


def _context_block(unit: CodeUnit) -> str:
    c = unit.context
    parts = []
    if c.get("imports"):
        parts.append("导入模块: " + ", ".join(c["imports"][:15]))
    if c.get("functions"):
        parts.append("本文件函数: " + ", ".join(c["functions"][:20]))
    if c.get("doc"):
        parts.append("文档字符串: " + c["doc"])
    return "\n".join(parts) or "（无附加上下文）"


def _hints_block(hints: list[Issue]) -> str:
    if not hints:
        return "（静态规则无命中，仍需独立判断）"
    return "\n".join(f"- 第 {h.line_start} 行疑似 {h.rule_id} {h.title}" for h in hints[:10])
