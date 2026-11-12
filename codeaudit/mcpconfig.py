# -*- coding: utf-8 -*-
"""MCP 客户端接入配置生成 + 子进程自检。

- client_config()：按当前运行形态（源码 / 绿色版 exe）生成可直接粘贴到
  Claude Desktop / Cursor 等客户端的 mcpServers 配置片段；
- selftest()：起一个真实 MCP 子进程走 initialize → tools/list → tools/call
  全握手，验证协议实现可用（不依赖任何外部客户端）。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .paths import ROOT


def client_config() -> dict:
    if getattr(sys, "frozen", False):
        entry = {"command": str(Path(sys.executable).resolve()), "args": ["--mcp"]}
        hint = "绿色版：把下面片段粘进客户端配置的 mcpServers 里即可（exe 路径已按本机生成）"
    else:
        entry = {"command": sys.executable, "args": ["-m", "codeaudit", "mcp"],
                 "cwd": str(ROOT)}
        hint = "源码运行：把下面片段粘进 Claude Desktop / Cursor 等客户端的 mcpServers 配置"
    return {"server_name": "llm-code-audit",
            "config": {"mcpServers": {"llm-code-audit": entry}},
            "hint": hint}


def selftest(timeout: float = 60.0) -> dict:
    """真实子进程握手自检：initialize → initialized → tools/list → 轻量工具调用。"""
    if getattr(sys, "frozen", False):
        cmd = [str(Path(sys.executable).resolve()), "--mcp"]
    else:
        cmd = [sys.executable, "-m", "codeaudit", "mcp"]
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "selftest", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "list_rules", "arguments": {}}},
    ]
    payload = "".join(json.dumps(m, ensure_ascii=False) + "\n" for m in msgs)
    try:
        proc = subprocess.run(cmd, input=payload.encode("utf-8"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=str(ROOT), timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "MCP 子进程握手超时"}
    except OSError as e:
        return {"ok": False, "error": f"无法启动 MCP 子进程：{e}"}
    lines = [ln for ln in proc.stdout.decode("utf-8", "replace").splitlines()
             if ln.strip()]
    try:
        resps = [json.loads(ln) for ln in lines]
    except json.JSONDecodeError:
        return {"ok": False, "error": "MCP 输出不是合法 JSON 行",
                "stderr": proc.stderr.decode("utf-8", "replace")[-300:]}
    by_id = {r.get("id"): r for r in resps}
    init = (by_id.get(1) or {}).get("result") or {}
    tools = ((by_id.get(2) or {}).get("result") or {}).get("tools") or []
    call = (by_id.get(3) or {}).get("result") or {}
    ok = bool(init.get("serverInfo")) and len(tools) >= 7 and not call.get("isError")
    out = {"ok": ok, "server": init.get("serverInfo", {}),
           "tools": [t["name"] for t in tools],
           "call_ok": not call.get("isError", True)}
    if not ok:
        out["stderr"] = proc.stderr.decode("utf-8", "replace")[-300:]
    return out
