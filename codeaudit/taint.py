# -*- coding: utf-8 -*-
"""跨文件污点追踪（近似）：外部输入源 → 危险汇聚点 的传播路径证据。

定位：调用图回答「谁调用了谁」，本模块再深一层回答「外部输入能不能流到
危险操作」——给 LLM 审计注入带行号的数据流证据链，而不是让它凭空推断。

工程折实（与 graph.py 同一哲学：名字解析近似，不做完整过程间分析）：
- source/sink 目录在 knowledge/taint/catalog.json，可维护、可评审；
- 函数内：参数默认视为潜在污点载体（外部可传入），局部变量经赋值传播
  （右式含 source 调用 / 污点名 / request 等外部输入特征即染色）；
- 跨函数：调用点实参含污点 → 被调函数对应形参染色，沿调用图迭代至不动点
  （上限 6 轮，防环）；self.method 与 import 别名复用 graph 的解析口径；
- 输出的是「候选传播路径」提示而非裁决——精确性由 LLM 层结合语义判断，
  分层降噪本意：静态层给证据，模型层做裁决。
零第三方依赖（内置 ast）；解析失败的文件静默跳过。
"""
from __future__ import annotations

import ast
import json
import os
import re
from collections import defaultdict
from pathlib import Path

from .parser import IGNORE_DIRS
from .paths import ROOT

CATALOG_FILE = ROOT / "knowledge" / "taint" / "catalog.json"

# 外部输入特征（表达式文本级）：web 请求/命令行/环境变量/标准输入
_EXTERNAL_RX = re.compile(
    r"\brequest\b|\bflask\b|\bargv\b|os\.environ|os\.getenv|\binput\s*\(|"
    r"sys\.stdin|\.args\b|\.form\b|\.json\b|\.data\b|\.values\b|\.cookies\b|"
    r"\bheaders\b|\.query_params\b|\.GET\b|\.POST\b")

# 字符串字面量遮蔽：文件名 ".json" 等文案不得撞外部输入特征（CONST 误染治理）
_STR_RX = re.compile(r"\"\"\".*?\"\"\"|'''.*?'''|\"[^\"\n]*\"|'[^'\n]*'", re.S)


def _strip_strings(text: str) -> str:
    return _STR_RX.sub('""', text)


def load_catalog() -> dict:
    try:
        return json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"sources": [], "sinks": []}


def _call_name(func: ast.expr) -> str:
    """调用目标 → 点分名字（os.system / cursor.execute / eval）。"""
    parts: list[str] = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _match_catalog(name: str, entries: list[dict]) -> dict | None:
    for e in entries:
        pat = e.get("match", "")
        if pat and (name == pat or name.endswith("." + pat)
                    or name.startswith(pat + ".")):
            return e
    return None


def _iter_scope(fn: ast.AST):
    """遍历函数体但剪掉嵌套作用域（嵌套 def/class 由 build 单独登记，
    lambda 体归外层但无独立赋值语义）——避免同一 sink 被外层与内层
    函数记录重复统计。"""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


class TaintTracker:
    """构建期：逐函数收集 source/sink/赋值/调用；迭代传播；查询期：出路径文本。"""

    def __init__(self, catalog: dict | None = None) -> None:
        cat = catalog if catalog is not None else load_catalog()
        self.sources: list[dict] = cat.get("sources", [])
        self.sinks: list[dict] = cat.get("sinks", [])
        # fqn → 函数记录
        self.funcs: dict[str, dict] = {}
        # (callee_fqn, arg_index) → 污点证据列表
        self.param_taint: dict[tuple[str, int], list[str]] = defaultdict(list)
        self.paths: list[dict] = []          # 最终候选传播路径
        self.file_mod: dict[str, str] = {}
        self.stats_d = {"files": 0, "functions": 0, "sources": 0,
                        "sinks": 0, "paths": 0, "rounds": 0}

    # ---------- 构建 ----------

    def build(self, root: Path, files: list[Path] | None = None) -> "TaintTracker":
        root = Path(root).resolve()
        files = files or [p for p in sorted(root.rglob("*.py"))
                          if not any(part in IGNORE_DIRS for part in p.parts)]
        from .graph import _collect_aliases, _mod_name, _resolve_callee
        parsed = []
        for f in files:
            try:
                tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
            except (SyntaxError, OSError, ValueError):
                continue
            mod = _mod_name(f, root)
            absf = str(f.resolve())
            self.file_mod[absf] = mod
            self.stats_d["files"] += 1
            parsed.append((tree, mod, absf))
        for tree, mod, absf in parsed:
            aliases = _collect_aliases(tree, mod)
            self._collect(tree, mod, absf, aliases, _resolve_callee)
        self._propagate()
        return self

    def _collect(self, tree: ast.Module, mod: str, absf: str,
                 aliases: dict, resolve) -> None:
        def visit(node: ast.AST, klass: str | None, fqn: str | None) -> None:
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nfqn = f"{mod}.{klass}.{ch.name}" if klass else f"{mod}.{ch.name}"
                    rec = {"file": absf, "line": ch.lineno, "args": [],
                           "tainted": set(), "assigns": [], "calls": [],
                           "sinks": [], "sources": []}
                    rec["args"] = [a.arg for a in ch.args.args
                                   if a.arg not in ("self", "cls")]
                    self.funcs[nfqn] = rec
                    self.stats_d["functions"] += 1
                    self._scan_body(ch, rec, mod, klass, aliases, resolve)
                    visit(ch, klass, nfqn)
                    continue
                if isinstance(ch, ast.ClassDef):
                    visit(ch, ch.name, fqn)
                    continue
                visit(ch, klass, fqn)
        visit(tree, None, None)

    def _scan_body(self, fn: ast.AST, rec: dict, mod: str, klass: str | None,
                   aliases: dict, resolve) -> None:
        for node in _iter_scope(fn):
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                src = _match_catalog(name, self.sources)
                if src:
                    rec["sources"].append({"line": node.lineno, "call": name,
                                           "cwe": src.get("cwe", "")})
                    self.stats_d["sources"] += 1
                sink = _match_catalog(name, self.sinks)
                if sink and self._sink_applicable(node, name):
                    rec["sinks"].append({
                        "line": node.lineno, "call": name,
                        "cwe": sink.get("cwe", ""),
                        "arg_names": [self._expr_names(a) for a in node.args],
                        "arg_text": [ast.unparse(a)[:80] for a in node.args]})
                    self.stats_d["sinks"] += 1
                callee = resolve(node.func, mod, klass, aliases)
                if callee:
                    rec["calls"].append({
                        "callee": callee, "line": node.lineno,
                        "arg_names": [self._expr_names(a) for a in node.args],
                        "arg_text": [ast.unparse(a)[:60] for a in node.args]})
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                t = node.targets[0]
                if isinstance(t, ast.Name):
                    rec["assigns"].append({
                        "var": t.id, "line": node.lineno,
                        "names": self._expr_names(node.value),
                        "text": ast.unparse(node.value)[:120],
                        "is_source": bool(_match_catalog(
                            _call_name(node.value.func), self.sources))
                        if isinstance(node.value, ast.Call) else False})

    # 方法名撞车治理（对齐 Python 规则层 NAME 口径）：open/eval/exec 只认
    # 裸内置调用；self.open / frame.eval 等属性调用是同名方法，不是该 sink
    _BARE_SINKS = {"open", "eval", "exec"}

    def _sink_applicable(self, node: ast.Call, name: str) -> bool:
        last = name.rsplit(".", 1)[-1]
        if last in self._BARE_SINKS and not isinstance(node.func, ast.Name) \
                and not name.startswith("builtins."):
            self.stats_d["filtered_bare"] = self.stats_d.get("filtered_bare", 0) + 1
            return False
        # 内存对象非路径：send_file(BytesIO(...)) 不构成路径遍历（TYPE 治理）
        if name.endswith("send_file") and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Call) and _call_name(a0.func).rsplit(".", 1)[-1] \
                    in ("BytesIO", "StringIO"):
                self.stats_d["filtered_buffer"] = \
                    self.stats_d.get("filtered_buffer", 0) + 1
                return False
        return True

    @staticmethod
    def _expr_names(expr: ast.expr) -> set[str]:
        """表达式里出现的名字集合（含属性链根名），用于污点传播判定。"""
        out: set[str] = set()
        for n in ast.walk(expr):
            if isinstance(n, ast.Name):
                out.add(n.id)
        return out

    # ---------- 传播 ----------

    def _propagate(self, max_rounds: int = 6) -> None:
        # 初始染色：source 调用赋值 + 外部输入特征赋值（字符串遮蔽后判定）；
        # __file__ 派生的仓库内常量路径不染色（CONST 治理）；
        # parse_args 派生变量染 CLI 信任色（本地工具自有参数，非攻击面）
        for fqn, rec in self.funcs.items():
            rec["cli_vars"] = set()
            for a in rec["assigns"]:
                masked = _strip_strings(a["text"])
                if "__file__" in masked and not a["is_source"]:
                    self.stats_d["filtered_const"] = \
                        self.stats_d.get("filtered_const", 0) + 1
                    continue
                if a["is_source"] or _EXTERNAL_RX.search(masked) \
                        or "parse_args(" in masked:
                    rec["tainted"].add(a["var"])
                    if "parse_args(" in masked:
                        rec["cli_vars"].add(a["var"])
        for rnd in range(max_rounds):
            changed = False
            for fqn, rec in self.funcs.items():
                tainted = rec["tainted"]
                cli = rec["cli_vars"]
                # 函数内赋值传播（右式引用已染色名字）；全由 CLI 色传入则继承 CLI 色
                for a in rec["assigns"]:
                    hit = a["names"] & tainted
                    if a["var"] not in tainted and hit:
                        tainted.add(a["var"])
                        changed = True
                        if hit <= cli:
                            cli.add(a["var"])
                # 跨函数：实参含污点 → 被调函数形参染色
                for c in rec["calls"]:
                    callee = self.funcs.get(c["callee"])
                    if callee is None:
                        continue
                    for idx, names in enumerate(c["arg_names"]):
                        if idx >= len(callee["args"]):
                            break
                        if names & tainted:
                            param = callee["args"][idx]
                            key = (c["callee"], idx)
                            ev = f"{fqn}({Path(rec['file']).name}:{c['line']})"
                            if param not in callee["tainted"]:
                                callee["tainted"].add(param)
                                changed = True
                            if ev not in self.param_taint[key]:
                                self.param_taint[key].append(ev)
                                changed = True
            self.stats_d["rounds"] = rnd + 1
            if not changed:
                break
        # 汇总候选路径：sink 实参引用了染色名字（或本身是外部输入表达式）；
        # 纯 CLI 信任色的流默认过滤（AUDIT_TAINT_CLI=1 可保留供本地工具审计）
        keep_cli = os.getenv("AUDIT_TAINT_CLI", "0") == "1"
        for fqn, rec in self.funcs.items():
            for s in rec["sinks"]:
                for idx, names in enumerate(s["arg_names"]):
                    hit_vars = names & rec["tainted"]
                    text = s["arg_text"][idx] if idx < len(s["arg_text"]) else ""
                    external = bool(_EXTERNAL_RX.search(_strip_strings(text)))
                    if not hit_vars and not external:
                        continue
                    if hit_vars and hit_vars <= rec["cli_vars"] and not external \
                            and not keep_cli:
                        self.stats_d["filtered_cli"] = \
                            self.stats_d.get("filtered_cli", 0) + 1
                        continue
                    origin = self._origin(fqn, rec, hit_vars)
                    self.paths.append({
                        "sink_fqn": fqn, "file": rec["file"],
                        "line": s["line"], "call": s["call"],
                        "cwe": s["cwe"], "vars": sorted(hit_vars),
                        "origin": origin, "external": external})
        self.stats_d["paths"] = len(self.paths)

    def _origin(self, fqn: str, rec: dict, hit_vars: set[str]) -> str:
        """回溯污点来源：本函数 source 调用 / 外部输入赋值 / 调用方传入。"""
        for a in rec["assigns"]:
            if a["var"] in hit_vars:
                if a["is_source"]:
                    return f"source 调用（{Path(rec['file']).name}:{a['line']}）"
                if _EXTERNAL_RX.search(a["text"]):
                    return f"外部输入（{Path(rec['file']).name}:{a['line']}）"
        for idx, param in enumerate(rec["args"]):
            if param in hit_vars and self.param_taint.get((fqn, idx)):
                return "调用方传入：" + "; ".join(self.param_taint[(fqn, idx)][:2])
        return "外部输入表达式直达"

    # ---------- 查询 ----------

    def paths_for_file(self, path: str | Path, limit: int = 8) -> list[dict]:
        absf = str(Path(path).resolve())
        return [p for p in self.paths if p["file"] == absf][:limit]

    def file_text(self, path: str | Path, limit: int = 8) -> str:
        rows = self.paths_for_file(path, limit)
        if not rows:
            return ""
        lines = ["跨文件污点传播候选路径（静态近似，需结合语义确认）:"]
        for p in rows:
            via = "、".join(p["vars"]) or "外部输入"
            lines.append(f"- 第{p['line']}行 {p['call']}（{p['cwe']}）"
                         f" ← 变量[{via}] ← {p['origin']}")
        return "\n".join(lines)

    def function_text(self, path: str | Path, fname: str, limit: int = 5) -> str:
        absf = str(Path(path).resolve())
        rows = [p for p in self.paths
                if p["file"] == absf and p["sink_fqn"].endswith("." + fname)][:limit]
        if not rows:
            return ""
        lines = ["本函数内的污点汇聚候选（静态近似）:"]
        for p in rows:
            via = "、".join(p["vars"]) or "外部输入"
            lines.append(f"- 第{p['line']}行 {p['call']}（{p['cwe']}）"
                         f" ← [{via}] ← {p['origin']}")
        return "\n".join(lines)

    def stats(self) -> dict:
        return dict(self.stats_d)
