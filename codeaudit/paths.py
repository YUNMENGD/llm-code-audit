# -*- coding: utf-8 -*-
"""资源根路径统一解析（绿色版打包关键）。

开发态：ROOT = 仓库根（行为与历史完全一致）。
冻结态（PyInstaller onedir 双击 exe）：ROOT = exe 所在目录——
knowledge/ prompts/ web/ data/ 全部以「exe 旁的可编辑文件」形态分发：
队友改知识库、换提示词、放 .env 都无需重新打包。
"""
from __future__ import annotations

import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent.parent

KNOWLEDGE_DIR = ROOT / "knowledge" / "defects"
RULES_DIR = ROOT / "knowledge" / "rules"
PROMPTS_DIR = ROOT / "prompts"
WEB_DIR = ROOT / "web"
DATA_DIR = ROOT / "data"
