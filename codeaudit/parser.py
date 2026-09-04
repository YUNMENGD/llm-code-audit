"""代码解析与多粒度切分。

当前实现 Python（内置 ast，零依赖）；Java/C++ 在 D14 前通过 tree-sitter 扩展，
接口（parse_project / parse_file / split_functions）保持不变。
"""
from __future__ import annotations

import ast
from pathlib import Path

from .models import CodeUnit

IGNORE_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules",
               "out", "data", ".cache", "build", "dist"}


def parse_project(root: str | Path) -> CodeUnit:
    """工程级单元：目录树 + 每个文件的结构摘要（导入/函数/类签名）。"""
    root = Path(root)
    files = [p for p in sorted(root.rglob("*.py"))
             if not any(part in IGNORE_DIRS for part in p.parts)
             and ".venv" not in p.parts]
    summaries: list[str] = []
    for p in files[:200]:                     # 工程级摘要控制规模
        try:
            summaries.append(_file_summary(p))
        except SyntaxError:
            summaries.append(f"{p.relative_to(root)}: (语法错误，无法解析)")
    tree = _tree_lines(root, files)
    return CodeUnit(
        kind="project",
        name=root.name,
        path=str(root),
        source=tree + "\n\n" + "\n\n".join(summaries),
        line_start=1,
        line_end=tree.count("\n") + len(summaries) * 6 + 2,
        context={"file_count": len(files), "files": [str(f) for f in files]},
    )


def parse_file(path: str | Path) -> CodeUnit:
    """文件级单元：完整源码 + 结构上下文（模块 docstring/导入/函数名列表）。"""
    path = Path(path)
    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source)
        imports = _collect_imports(tree)
        names = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        doc = ast.get_docstring(tree) or ""
    except SyntaxError:
        imports, names, doc = [], [], ""
    context = {"imports": imports, "functions": names, "doc": doc[:500]}
    return CodeUnit(
        kind="file", name=path.stem, path=str(path),
        source=source, line_start=1,
        line_end=max(len(source.splitlines()), 1), context=context,
    )


def split_functions(unit: CodeUnit) -> list[CodeUnit]:
    """把一个文件单元切分为函数级单元（含起止行号，喂给函数级 Prompt）。"""
    if unit.kind != "file":
        return []
    try:
        tree = ast.parse(unit.source)
    except SyntaxError:
        return []
    lines = unit.source.splitlines()
    out: list[CodeUnit] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
        end = getattr(node, "end_lineno", start) or start
        src = "\n".join(lines[start - 1:end])
        out.append(CodeUnit(
            kind="function", name=node.name, path=unit.path,
            source=src, line_start=start, line_end=end,
            context={"imports": unit.context.get("imports", []),
                     "doc": (ast.get_docstring(node) or "")[:300]},
        ))
    return out


def parse_sources(source: str, name: str = "<inline>") -> list[CodeUnit]:
    """从字符串源码生成 文件级 + 函数级 单元（CLI 单文件审计用）。"""
    unit = CodeUnit(kind="file", name=Path(name).stem, path=name, source=source,
                    line_start=1, line_end=max(len(source.splitlines()), 1),
                    context={})
    try:
        tree = ast.parse(source)
        unit.context["imports"] = _collect_imports(tree)
        unit.context["functions"] = [n.name for n in ast.walk(tree)
                                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    except SyntaxError:
        return [unit]
    return [unit, *split_functions(unit)]


def _collect_imports(tree: ast.AST) -> list[str]:
    mods: list[str] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom) and n.module:
            mods.append(n.module)
    return sorted(set(mods))


def _file_summary(path: Path) -> str:
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return f"{path}: (语法错误)"
    items = []
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = ", ".join(a.arg for a in n.args.args[:4])
            items.append(f"def {n.name}({args})")
        elif isinstance(n, ast.ClassDef):
            methods = [m.name for m in n.body
                       if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))][:6]
            items.append(f"class {n.name}: {', '.join(methods)}")
    return f"{path.name} ({len(src.splitlines())} 行): " + "; ".join(items[:20])


def _tree_lines(root: Path, files: list[Path], max_show: int = 60) -> str:
    lines = [f"{root.name}/"]
    shown = 0
    for f in files:
        if shown >= max_show:
            lines.append(f"  ... 共 {len(files)} 个文件")
            break
        lines.append(f"  {f.relative_to(root).as_posix()}")
        shown += 1
    return "\n".join(lines)
