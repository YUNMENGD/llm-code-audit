# -*- coding: utf-8 -*-
"""Git pre-commit 钩子生成器（可选）：提交前自动增量审计 + 门禁。

本模块提供脚本渲染与安装/卸载函数；安装必须由用户显式执行
（python -m codeaudit hook --install），自动化流程不会替你写 .git。
临时跳过：SKIP_CODEAUDIT=1 git commit ...
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

TEMPLATE = """#!/bin/sh
# 明查秋毫 pre-commit 钩子：提交前只审本次变更文件，达到阈值即拦截提交。
# 临时跳过：SKIP_CODEAUDIT=1 git commit ...
if [ "$SKIP_CODEAUDIT" = "1" ]; then
  exit 0
fi
PY="{python}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi
"$PY" -m codeaudit check . --changed-since HEAD
CODE=$?
if [ $CODE -ne 0 ]; then
  echo ""
  echo "[codeaudit] 发现高危及以上问题，提交已拦截。"
  echo "  修复后重试，或临时跳过：SKIP_CODEAUDIT=1 git commit ..."
  exit 1
fi
exit 0
"""


def render(threshold: str = "high", python: str = "python") -> str:
    if threshold not in ("critical", "high", "medium", "low"):
        raise ValueError("阈值必须是 critical/high/medium/low")
    body = TEMPLATE.format(python=python)
    if threshold != "high":
        body = body.replace("--changed-since HEAD",
                            "--changed-since HEAD --min-severity " + threshold)
        body = body.replace("发现高危及以上问题", "发现 %s 及以上问题" % threshold)
    return body


def hook_path(repo) -> Path:
    return Path(repo) / ".git" / "hooks" / "pre-commit"


def install(repo, threshold: str = "high", python: str = "python",
            force: bool = False) -> dict:
    p = hook_path(repo)
    if not (Path(repo) / ".git").exists():
        return {"ok": False, "note": "目标不是 git 仓库"}
    if p.exists() and not force:
        return {"ok": False, "note": "已存在 pre-commit 钩子，加 --force 覆盖",
                "path": str(p)}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render(threshold, python), encoding="utf-8", newline="\n")
    try:
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    except OSError:
        pass
    return {"ok": True, "path": str(p), "threshold": threshold}


def uninstall(repo) -> dict:
    p = hook_path(repo)
    if not p.exists():
        return {"ok": False, "note": "未安装钩子"}
    body = p.read_text(encoding="utf-8", errors="replace")
    if "codeaudit" not in body:
        return {"ok": False, "note": "该钩子不是本工具生成的，未删除"}
    p.unlink()
    return {"ok": True}
