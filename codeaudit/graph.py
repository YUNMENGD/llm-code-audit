"""跨文件函数调用图（申报书研究内容①"函数调用链/跨文件依赖"的静态近似）。

定位：给 LLM 审计注入调用关系上下文——"这个文件/函数的外部调用方是谁、
它又调了谁"，让"影响范围"字段第一次有代码证据链，而不是模型编。

工程折实：完整跨过程分析（points-to/context-sensitive）超出项目范围且有
现成工具；本模块做**名字解析近似**：
  · 模块级/类方法定义登记为 fqn（模块.类.方法）
  · 调用点解析：本文件 def → import 别名（含相对导入）→ self.method（类内）
    → 其余记 unresolved（框架动态派发是主因，交 LLM 层做语义判断——分层本意）
零依赖（内置 ast）；解析失败的文件静默跳过，不拉闸整图。
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from .parser import IGNORE_DIRS

_BUILTIN_NOISE = {"print", "len", "isinstance", "super", "getattr",
                  "setattr", "hasattr", "open", "range", "dict", "list",
                  "set", "tuple", "str", "int", "float", "bool", "type"}


def _mod_name(path: Path, root: Path) -> str:
    """文件 → 近似模块名；__init__.py 归并为包名。"""
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        rel = Path(path.name)
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__.py":
        parts.pop()
    elif parts:
        parts[-1] = parts[-1][:-3] if parts[-1].endswith(".py") else parts[-1]
    return ".".join(parts)


class CallGraph:
    """defs: fqn→(file,line)；edges: caller→callee 调用点列表（带位置）。"""

    def __init__(self) -> None:
        self.defs: dict[str, tuple[str, int]] = {}
        self.file_mod: dict[str, str] = {}
        self.edges: list[tuple[str, str, str, int]] = []
        self._callers_idx: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        self._callees_idx: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        self.files = 0
        self.unresolved = 0

    # ---------- 构建 ----------

    def build(self, root: Path, files: list[Path] | None = None) -> "CallGraph":
        root = Path(root).resolve()
        files = files or [p for p in sorted(root.rglob("*.py"))
                          if not any(part in IGNORE_DIRS for part in p.parts)]
        parsed: list[tuple[Path, ast.Module, str]] = []
        for f in files:
            try:
                tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
            except (SyntaxError, OSError, ValueError):
                continue
            mod = _mod_name(f, root)
            absf = str(f.resolve())
            self.file_mod[absf] = mod
            self.files += 1
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.defs[f"{mod}.{node.name}"] = (absf, node.lineno)
                elif isinstance(node, ast.ClassDef):
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self.defs[f"{mod}.{node.name}.{sub.name}"] = (
                                absf, sub.lineno)
            parsed.append((f, tree, mod))
        for f, tree, mod in parsed:
            absf = str(f.resolve())
            aliases = _collect_aliases(tree, mod)
            self._walk_calls(tree, mod, absf, aliases)
        return self

    def _register_edge(self, caller: str, callee: str,
                       file: str, line: int) -> None:
        if caller == callee:
            return
        self.edges.append((caller, callee, file, line))
        self._callers_idx[callee].append((caller, file, line))
        self._callees_idx[caller].append((callee, file, line))

    def _walk_calls(self, tree: ast.Module, mod: str, absf: str,
                    aliases: dict[str, str]) -> None:
        def visit(node: ast.AST, klass: str | None, caller: str | None) -> None:
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    visit(ch, klass, f"{mod}.{klass}.{ch.name}" if klass
                          else f"{mod}.{ch.name}")
                    continue
                if isinstance(ch, ast.ClassDef):
                    visit(ch, ch.name, caller)
                    continue
                if isinstance(ch, ast.Call) and caller:
                    callee = _resolve_callee(ch.func, mod, klass, aliases)
                    if callee and callee in self.defs:
                        self._register_edge(caller, callee, absf, ch.lineno)
                    else:
                        self.unresolved += 1
                visit(ch, klass, caller)
        visit(tree, None, None)          # 模块级调用点无 caller，忽略

    # ---------- 查询（注入文本生成） ----------

    def external_callers_text(self, path: str | Path, limit: int = 12) -> str:
        """本文件的函数被哪些【其他模块】调用——影响范围证据。"""
        absf = str(Path(path).resolve())
        mod = self.file_mod.get(absf)
        if not mod:
            return ""
        lines: list[str] = []
        seen: set[tuple[str, str]] = set()
        for callee, inc in self._callers_idx.items():
            if not callee.startswith(mod + "."):
                continue
            for caller, cfile, cline in inc:
                if caller.startswith(mod + "."):
                    continue             # 文件内部调用不算影响面
                if (caller, callee) in seen:
                    continue
                seen.add((caller, callee))
                lines.append(f"{callee}  ←  {caller}  ({Path(cfile).name}:{cline})")
                if len(lines) >= limit:
                    return "\n".join(lines)
        return "\n".join(lines)

    def function_calls_text(self, path: str | Path, fname: str,
                            limit: int = 8) -> tuple[str, str]:
        """(外部调用方, 本函数调出的项目内目标) 两段列表。"""
        absf = str(Path(path).resolve())
        mod = self.file_mod.get(absf, "")
        fqns = [f"{mod}.{fname}"] + [
            d for d, (fp, _) in self.defs.items()
            if fp == absf and d.endswith(f".{fname}") and d != f"{mod}.{fname}"]
        callers: list[str] = []
        callees: list[str] = []
        for fqn in fqns:
            for c, cf, cl in self._callers_idx.get(fqn, []):
                callers.append(f"{c}({Path(cf).name}:{cl})")
            for c, cf, cl in self._callees_idx.get(fqn, []):
                callees.append(c)
            if callers or callees:
                break
        return ("; ".join(callers[:limit]), "; ".join(dict.fromkeys(callees))[:200])

    def stats(self) -> dict:
        return {"files": self.files, "defs": len(self.defs),
                "edges": len(self.edges), "unresolved": self.unresolved}


def _collect_aliases(tree: ast.Module, mod: str) -> dict[str, str]:
    """名字 → 目标模块路径。覆盖 import a.b [as c] / from x import y [as z] /
    相对导入（from . import y、from .z import w、from ..pkg import f）。"""
    out: dict[str, str] = {}
    pkg_parts = mod.split(".")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = pkg_parts[:len(pkg_parts) - (node.level - 1) -
                                       (0 if _is_package(mod) else 1)]
                base = ".".join(base_parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            for a in node.names:
                if a.name == "*":
                    continue
                out[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
    return out


def _is_package(mod: str) -> bool:
    """模块名对应包（__init__）还是模块——近似：无法静态确知，取保守 False。
    包内 `from . import x` 时 base=当前模块所在包；若当前是模块则多剥一层。
    调用方文件恰为包 __init__ 的少数情形容忍偏差（图是上下文提示非裁决）。"""
    return False


def _resolve_callee(func: ast.expr, mod: str, klass: str | None,
                    aliases: dict[str, str]) -> str | None:
    if isinstance(func, ast.Name):
        n = func.id
        if n in _BUILTIN_NOISE:
            return None
        if klass and f"{mod}.{klass}.{n}" not in aliases:
            pass
        cand = f"{mod}.{n}"
        if n in aliases:
            return aliases[n]
        return cand
    if isinstance(func, ast.Attribute):
        chain: list[str] = []
        cur: ast.expr = func
        while isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            return None                 # 调用结果链 f().g()：不可静态解析
        root_name = cur.id
        if root_name == "self":
            if not klass:
                return None
            return f"{mod}.{klass}.{'.'.join(reversed(chain))}"
        prefix = aliases.get(root_name) or (f"{mod}.{root_name}"
                                            if root_name[0].isupper() else None)
        if prefix:
            return prefix + "." + ".".join(reversed(chain))
        if root_name == mod.split(".")[-1]:
            return mod + "." + ".".join(reversed(chain))
        return None
    return None
