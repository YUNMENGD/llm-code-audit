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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import cache as C
from . import parser as P
from . import retriever as R
from . import rules as RL
from . import validate as V
from .examples import examples_enabled, format_examples
from .llm import LLMClient, LLMError, extract_json_array
from .models import AuditReport, CodeUnit, Issue

PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts"


def load_prompt(name: str) -> str:
    f = PROMPT_DIR / name
    return f.read_text(encoding="utf-8") if f.exists() else ""


def audit_path(target: str | Path, depth: str = "file",
               use_examples: bool | None = None,
               cross_review: bool | None = None,
               use_cache: bool | None = None) -> AuditReport:
    """审计一个文件或目录。depth: function(逐函数) | file(整体) | project(工程级)

    use_examples: few-shot 校准示例开关；None 时读环境变量 PROMPT_EXAMPLES。
    cross_review: D15 双模型交叉复核开关；None 时读 AUDIT_CROSS_REVIEW。
    use_cache:    D17 增量缓存开关；None 时读 AUDIT_CACHE。
    """
    target = Path(target)
    started = time.time()
    client = LLMClient()
    reviewer = LLMClient.for_reviewer()
    if cross_review is None:
        cross_review = os.getenv("AUDIT_CROSS_REVIEW", "0") == "1"
    do_cross = cross_review and reviewer.available() and reviewer.model != client.model
    clients = [client] + ([reviewer] if do_cross else [])
    use_cache = C.enabled(use_cache)
    static_rules = RL.load_rules()
    knowledge = R.load_knowledge()
    use_examples = examples_enabled(use_examples)
    cache_stat = {"hit": 0, "miss": 0}
    issues: list[Issue] = []
    engine = {"model": client.model if client.available() else "static-only",
              "depth": depth, "llm_used": False, "units": 0,
              "examples": use_examples,
              "cross_review": do_cross,
              "reviewer": reviewer.model if do_cross else None,
              "cache": use_cache}

    files = [target] if target.is_file() else sorted(
        p for p in target.rglob("*.py")
        if not any(part in P.IGNORE_DIRS for part in p.parts))

    n_files = len(files)
    for fi, f in enumerate(files, 1):
        if engine["llm_used"] or n_files > 1:
            print(f"[{fi}/{n_files}] 解析 {f} ...", flush=True)
        file_unit = P.parse_file(f)
        source_lines = file_unit.source.splitlines()

        # ① 静态硬性规则
        issues += RL.scan_source(file_unit.source, static_rules, str(f))

        # ② LLM 审计（未配置密钥则跳过，系统仍可输出静态结果）
        units: list[CodeUnit] = []
        if do_cross or client.available():
            engine["llm_used"] = True
            if depth == "function":
                units = P.split_functions(file_unit) or [file_unit]
            elif depth == "project" and target.is_dir():
                units = [P.parse_project(target)]
            else:
                units = [file_unit]
            active = [cu for cu in clients if cu.available()]
            tasks = [(cu, u) for cu in active for u in units]
            total_calls = len(tasks)
            engine["units"] += total_calls
            done = 0
            with ThreadPoolExecutor(max_workers=_concurrency(total_calls)) as pool:
                futs = {pool.submit(_audit_unit, cu, u, source_lines,
                                    static_rules, knowledge, use_examples,
                                    use_cache): (cu, u) for cu, u in tasks}
                for fut in as_completed(futs):
                    cu, u = futs[fut]
                    done += 1
                    found, hit = fut.result()
                    if hit is True:
                        cache_stat["hit"] += 1
                    elif hit is False:
                        cache_stat["miss"] += 1
                    src = {True: "缓存", False: "模型", None: "模型"}[hit]
                    tag = "共识" if do_cross else "审计"
                    print(f"  [{done}/{total_calls}] {tag} {u.kind} "
                          f"{u.name} ({cu.model}) → {len(found)} 条候选 [{src}]",
                          flush=True)
                    issues += found
    if use_cache:
        C.flush()

    # ③ 校验管线：去重 → 跨源CWE合并(T3) → 幻觉过滤 → rule_id白名单 → 双模型复核(D15) → 置信度闸门(T2)
    valid_ids = {it["id"] for it in knowledge} | {r["id"] for r in static_rules}
    before = len(issues)
    issues = V.dedupe(issues)
    issues = V.cwe_merge(issues)
    issues = [i for i in issues if not (i.detector == "llm" and not i.verified)]
    issues = V.rule_id_gate(issues, valid_ids)
    agreement = V.cross_review(issues, enabled=do_cross, n_models=len(clients))
    issues = V.confidence_gate(issues)
    filtered = before - len(issues)
    consistency_runs = int(os.getenv("AUDIT_CONSISTENCY_RUNS", "1"))

    report = AuditReport(
        target=str(target),
        issues=issues,
        engine={**engine, "consistency_runs": consistency_runs,
                "knowledge_loaded": len(knowledge), "rules_loaded": len(static_rules)},
    )
    report.stats = {
        "total": len(issues),
        "raw_before_validation": before,
        "filtered_out": filtered,
        "cross_review": agreement,
        "cache": cache_stat if use_cache else None,
        "by_severity": report.count_by("severity"),
        "by_category": report.count_by("category"),
        "by_detector": report.count_by("detector"),
        "elapsed_sec": round(time.time() - started, 2),
    }
    return report


def _concurrency(n_tasks: int) -> int:
    """并发度：min(AUDIT_CONCURRENCY 或 6, 任务数, 10)。"""
    cap = int(os.getenv("AUDIT_CONCURRENCY", "6"))
    return max(1, min(cap, n_tasks, 10))


def _audit_unit(client: LLMClient, unit: CodeUnit, source_lines: list[str],
                static_rules: list[dict], knowledge: list[dict],
                use_examples: bool = True,
                use_cache: bool = False) -> tuple[list[Issue], bool | None]:
    """单个工作单元的 LLM 审计：检索知识 → 组 Prompt → (缓存/调用) → 解析 → 校验。

    返回 (issues, cache_hit)。cache_hit: True 命中 / False 未命中 / None 未启用缓存。
    缓存键 = 模型名 + 完整 Prompt：代码、检索知识、few-shot、模板任一变化即 miss。
    """
    hints = RL.scan_source(unit.source, static_rules, unit.path)
    query = unit.source[:3000] + " " + " ".join(unit.context.get("imports", []))
    hits = R.retrieve(query, top_k=5, items=knowledge)

    tpl = load_prompt(f"{unit.kind}_audit.md") or load_prompt("file_audit.md")
    ex_kind = "file" if unit.kind == "project" else unit.kind
    prompt = (tpl
              .replace("{{language}}", "Python")
              .replace("{{scope}}", f"{unit.kind}: {unit.name}")
              .replace("{{context}}", _context_block(unit))
              .replace("{{knowledge}}", R.format_for_prompt(hits))
              .replace("{{hints}}", _hints_block(hints))
              .replace("{{examples}}",
                       format_examples(ex_kind) if use_examples else "")
              .replace("{{code}}", unit.tagged()))

    key = C.cache_key(prompt, client.model) if use_cache else None
    raw: str | None = C.get(key) if key else None
    hit: bool | None = None
    if raw is not None:
        hit = True
    else:
        hit = False if use_cache else None
        messages = [
            {"role": "system", "content": "你是资深代码审计专家，只输出符合要求的 JSON，不输出任何解释文字。"},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = client.chat(messages)
            if key:
                C.put(key, raw, model=client.model)
        except LLMError as e:
            print(f"[warn] 模型调用失败({unit.path}): {e}")
            return [], hit

    out: list[Issue] = []
    for item in extract_json_array(raw or ""):
        if not isinstance(item, dict):
            continue
        issue = Issue.from_dict(item, path=unit.path, detector="llm",
                                 model=client.model)
        ok, reason = V.check_with_rules(issue, source_lines)
        issue.verified = ok
        if not ok:
            issue.analysis = f"[校验未通过:{reason}] {issue.analysis}"
        out.append(issue)
    return out, hit


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
