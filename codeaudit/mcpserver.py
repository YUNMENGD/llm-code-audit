# -*- coding: utf-8 -*-
"""MCP 服务器（stdio，JSON-RPC 2.0）——把审计能力开放给任意 MCP 客户端。

零第三方依赖：按行读 stdin、按行写 stdout，实现 MCP 生命周期子集
（initialize / notifications/initialized / ping / tools/list / tools/call）。
stdout 只允许出现协议消息；引擎的进度 print 全部重定向到 stderr。

工具（6 个）：
  audit_code          审计文件/目录（默认静态；mode=ai 需已配置模型密钥）
  list_rules          列出硬性规则库
  search_knowledge    按代码特征检索缺陷知识库
  list_knowledge      列出知识库条目摘要
  mark_false_positive 误报标记入队（数据飞轮）
  audit_history       最近审计历史摘要

启动：python -m codeaudit mcp   （客户端配置由 /api/mcp/config 生成）
"""
from __future__ import annotations

import contextlib
import json
import sys

SERVER_NAME = "llm-code-audit"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "audit_code",
        "description": "审计一个 Python 文件或目录，返回问题清单（定位/证据/修复建议）。"
                       "默认静态规则模式（免费秒级）；mode=ai 走大模型深度审计（需已配置密钥）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "本机 .py 文件或目录的绝对路径"},
                "mode": {"type": "string", "enum": ["static", "ai"], "default": "static"},
                "depth": {"type": "string", "enum": ["function", "file", "project"],
                          "default": "file", "description": "AI 模式审计粒度"},
                "incremental": {"type": "boolean", "default": False,
                                "description": "只审 git 相对 HEAD 的变更文件"},
                "fail_on": {"type": "string",
                            "enum": ["none", "low", "medium", "high", "critical"],
                            "default": "none", "description": "门禁阈值：存在≥该严重度问题时 gate=failed"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "list_rules",
        "description": "列出静态硬性规则库（id/标题/严重度/正则），不含内置保护标记以外的管理操作。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "search_knowledge",
        "description": "按代码片段或关键词检索缺陷知识库，返回最相关条目（含缺陷模式/危害/修复要点/来源）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "代码片段或特征关键词"},
                "top_k": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "list_knowledge",
        "description": "列出知识库全部条目摘要（id/标题/类别/严重度/来源文件）。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "mark_false_positive",
        "description": "把一条审计发现标记为疑似误报，写入本地反馈队列（去重累计计数，供豁免候选评审）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule": {"type": "string", "description": "规则/知识 ID，如 R-SEC-001 或 CWE-89"},
                "title": {"type": "string"},
                "path": {"type": "string", "default": ""},
                "line": {"type": "integer"},
                "detector": {"type": "string", "default": ""},
                "evidence": {"type": "string", "default": ""},
            },
            "required": ["rule", "title"],
        },
    },
    {
        "name": "audit_history",
        "description": "列出最近的审计历史摘要（时间/目标/模式/问题数），默认 10 条。",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 10}},
        },
    },
    {
        "name": "diff_audits",
        "description": "对比两次审计历史（按历史 ID），返回新增/消除/行号移动/存续问题清单。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "old_id": {"type": "string", "description": "旧审计历史 ID"},
                "new_id": {"type": "string", "description": "新审计历史 ID"},
                "drift": {"type": "integer", "default": 3,
                          "description": "行号漂移容忍"},
            },
            "required": ["old_id", "new_id"],
        },
    },
]


def _tool_audit_code(args: dict) -> dict:
    from pathlib import Path

    from . import rules as RL
    from .audit import audit_path
    from .models import AuditReport, Severity

    target = str(args.get("target", "")).strip()
    if not target or not Path(target).exists():
        raise ValueError(f"目标路径不存在：{target}")
    mode = args.get("mode", "static")
    only = None
    if args.get("incremental"):
        from .gitdiff import GitUnavailable, git_changed_files
        p = Path(target)
        try:
            only = git_changed_files(p if p.is_dir() else p.parent, base="HEAD")
        except GitUnavailable as e:
            raise ValueError(f"增量审计不可用：{e}")
    if mode == "ai":
        rep = audit_path(target, depth=args.get("depth", "file"), only_files=only)
    else:
        from . import jsrules as JR
        p = Path(target)
        files = [p] if p.is_file() else sorted(
            f for f in p.rglob("*")
            if f.is_file() and f.suffix in ({".py"} | JR.JS_EXTS)
            and not any(x in f.parts for x in (".git", "__pycache__", ".venv",
                                               "venv", "node_modules")))
        if only is not None:
            files = [f for f in files if str(f.resolve()) in only]
        rs = RL.load_rules()
        js_rs = JR.load_js_rules()
        rep = AuditReport(target=target)
        for f in files:
            src = f.read_text(encoding="utf-8", errors="replace")
            if f.suffix in JR.JS_EXTS:
                rep.issues.extend(JR.scan_js_source(src, js_rs, str(f)))
            else:
                rep.issues.extend(RL.scan_source(src, rs, str(f)))
        rep.engine = {"model": "static-rules", "llm_used": False}
        rep.stats = {"total": len(rep.issues),
                     "by_severity": rep.count_by("severity"),
                     "by_category": rep.count_by("category"),
                     "by_detector": rep.count_by("detector")}
    gate = "off"
    fail_on = args.get("fail_on", "none")
    if fail_on != "none":
        order = [s.value for s in Severity]
        thr = order.index(fail_on)
        bad = [i for i in rep.issues if order.index(i.severity.value) <= thr]
        gate = "failed" if bad else "passed"
    return {
        "target": target, "mode": mode, "gate": gate,
        "total": len(rep.issues), "stats": rep.stats, "engine": rep.engine,
        "issues": [{"rule_id": i.rule_id, "severity": i.severity.value,
                    "title": i.title, "path": i.path, "line": i.line_start,
                    "evidence": i.evidence, "fix": i.fix,
                    "detector": i.detector}
                   for i in rep.sorted_issues()[:100]],
    }


def _tool_list_rules(args: dict) -> dict:
    from . import kbadmin as KA
    rows = [{"id": r["id"], "title": r["title"], "severity": r.get("severity"),
             "category": r.get("category"), "pattern": r.get("pattern", ""),
             "builtin": r.get("_builtin", True)} for r in KA.list_rules()]
    return {"count": len(rows), "rules": rows}


def _tool_search_knowledge(args: dict) -> dict:
    from . import retriever as R
    query = str(args.get("query", ""))
    if not query.strip():
        raise ValueError("query 不能为空")
    hits = R.retrieve(query, top_k=int(args.get("top_k", 5)))
    return {"count": len(hits),
            "items": [{"id": it["id"], "title": it["title"],
                       "severity": it.get("severity"), "score": it.get("score"),
                       "pattern": it.get("pattern", ""), "fix": it.get("fix", ""),
                       "source": it.get("source", "")} for it in hits]}


def _tool_list_knowledge(args: dict) -> dict:
    from . import kbadmin as KA
    rows = [{"id": it["id"], "title": it["title"], "category": it.get("category"),
             "severity": it.get("severity"), "file": it.get("_file", "")}
            for it in KA.list_items()]
    return {"count": len(rows), "items": rows}


def _tool_mark_fp(args: dict) -> dict:
    from . import feedback as FB
    rec = FB.add({"rule": args.get("rule", ""), "title": args.get("title", ""),
                  "path": args.get("path", ""), "line": args.get("line"),
                  "detector": args.get("detector", ""),
                  "evidence": args.get("evidence", "")})
    return {"ok": True, "count": rec["count"], "key": rec["key"]}


def _tool_history(args: dict) -> dict:
    from . import history as HS
    rows = HS.list_history(int(args.get("limit", 10)))
    return {"count": len(rows), "items": rows}


def _tool_diff(args: dict) -> dict:
    from . import history as HS
    from .diff import diff_reports
    a = HS.load_report(str(args.get("old_id", "")))
    b = HS.load_report(str(args.get("new_id", "")))
    d = diff_reports(a, b, drift=int(args.get("drift", 3)))
    slim = lambda rows: [{"rule": i.get("rule_id"), "path": i.get("path"),
                          "line": i.get("line_start"), "title": i.get("title")}
                         for i in rows]
    return {"summary": d["summary"], "added": slim(d["added"]),
            "removed": slim(d["removed"]), "moved": d["moved"]}


_HANDLERS = {
    "audit_code": _tool_audit_code,
    "list_rules": _tool_list_rules,
    "search_knowledge": _tool_search_knowledge,
    "list_knowledge": _tool_list_knowledge,
    "mark_false_positive": _tool_mark_fp,
    "audit_history": _tool_history,
    "diff_audits": _tool_diff,
}


# ---------- resources：知识库条目只读暴露 ----------

def _resources_list() -> list[dict]:
    from . import kbadmin as KA
    out = [{"uri": "codeaudit://knowledge/index",
            "name": "知识库索引",
            "description": "全部缺陷知识条目摘要（JSON）",
            "mimeType": "application/json"}]
    for it in KA.list_items():
        out.append({"uri": f"codeaudit://knowledge/{it['id']}",
                    "name": f"{it['id']} {it.get('title', '')}",
                    "description": (it.get("pattern") or "")[:100],
                    "mimeType": "application/json"})
    return out


def _resources_read(uri: str) -> dict:
    import json as _json

    from . import kbadmin as KA
    if uri == "codeaudit://knowledge/index":
        rows = [{"id": it["id"], "title": it.get("title"),
                 "severity": it.get("severity"), "category": it.get("category")}
                for it in KA.list_items()]
        text = _json.dumps(rows, ensure_ascii=False, indent=1)
    elif uri.startswith("codeaudit://knowledge/"):
        kid = uri.rsplit("/", 1)[-1]
        match = [it for it in KA.list_items() if it["id"] == kid]
        if not match:
            raise ValueError(f"条目不存在：{kid}")
        text = _json.dumps(match[0], ensure_ascii=False, indent=1)
    else:
        raise ValueError(f"未知资源 URI：{uri}")
    return {"contents": [{"uri": uri, "mimeType": "application/json",
                          "text": text}]}


# ---------- prompts：审计话术模板 ----------

_PROMPT_DEFS = [
    {"name": "audit_file",
     "description": "生成一份文件级代码审计请求（分层降噪口径：先证据后裁决）",
     "arguments": [{"name": "code", "description": "待审计代码", "required": True},
                   {"name": "language", "description": "语言（默认 Python）",
                    "required": False}]},
    {"name": "review_false_positive",
     "description": "对一条告警做误报复核（要求给出可辩护的判定依据）",
     "arguments": [{"name": "alert", "description": "告警 JSON 或描述",
                    "required": True},
                   {"name": "code", "description": "相关代码上下文",
                    "required": False}]},
]


def _prompts_list() -> list[dict]:
    return _PROMPT_DEFS


def _prompts_get(name: str, args: dict) -> dict:
    if name == "audit_file":
        code = str(args.get("code", ""))
        lang = str(args.get("language", "Python"))
        text = (f"你是资深代码审计专家。请审计以下 {lang} 代码，"
                "只报告有代码证据支撑的问题，每条给出：规则/CWE ID、严重度"
                "（critical/high/medium/low）、行号、证据原文、分析、修复建议。"
                "没有把握的不要报。只输出 JSON 数组。\n\n```\n" + code + "\n```")
    elif name == "review_false_positive":
        alert = str(args.get("alert", ""))
        code = str(args.get("code", ""))
        text = ("请复核以下告警是否误报。判定必须基于代码证据："
                "若存在护栏/豁免惯例/适用边界越界，判 F 并说明模式；"
                "若缺陷真实存在，判 T 并给出触发路径；证据不足判 ?。\n\n"
                f"告警：{alert}\n\n代码上下文：\n```\n{code}\n```")
    else:
        raise ValueError(f"未知提示模板：{name}")
    return {"description": name,
            "messages": [{"role": "user",
                          "content": {"type": "text", "text": text}}]}


def handle(msg: dict) -> dict | None:
    """处理一条 JSON-RPC 消息；通知（无 id）返回 None。"""
    method = msg.get("method", "")
    mid = msg.get("id")
    params = msg.get("params") or {}

    def ok(result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": code, "message": message}}

    if mid is None:                      # 通知类：initialized / cancelled 等
        return None
    if method == "initialize":
        return ok({"protocolVersion": PROTOCOL_VERSION,
                   "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                   "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": _TOOLS})
    if method == "resources/list":
        return ok({"resources": _resources_list()})
    if method == "resources/read":
        try:
            return ok(_resources_read(params.get("uri", "")))
        except Exception as e:           # noqa: BLE001
            return err(-32602, f"资源读取失败：{e}")
    if method == "prompts/list":
        return ok({"prompts": _prompts_list()})
    if method == "prompts/get":
        try:
            return ok(_prompts_get(params.get("name", ""),
                                   params.get("arguments") or {}))
        except Exception as e:           # noqa: BLE001
            return err(-32602, f"提示模板获取失败：{e}")
    if method == "tools/call":
        name = params.get("name", "")
        handler = _HANDLERS.get(name)
        if handler is None:
            return err(-32602, f"未知工具：{name}")
        try:
            # 引擎进度 print 全部去 stderr，stdout 只走协议
            with contextlib.redirect_stdout(sys.stderr):
                result = handler(params.get("arguments") or {})
            return ok({"content": [{"type": "text",
                                    "text": json.dumps(result, ensure_ascii=False)}],
                       "isError": False})
        except Exception as e:           # noqa: BLE001 工具错误按 MCP 约定回 isError
            return ok({"content": [{"type": "text",
                                    "text": f"{type(e).__name__}: {e}"}],
                       "isError": True})
    return err(-32601, f"未知方法：{method}")


def serve() -> int:
    """按行读 stdin → 处理 → 按行写 stdout（MCP stdio 传输）。"""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "parse error"}}
        else:
            resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
