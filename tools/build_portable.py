# -*- coding: utf-8 -*-
"""绿色版打包（onedir）：PyInstaller 冻结入口 + exe 旁分发可编辑数据。

用法：python tools/build_portable.py
产物：dist/CodeAudit/  —— 整个文件夹拷给队友，双击 CodeAudit.exe 即用。

设计：
- 数据不塞进 exe：knowledge/ prompts/ web/ .env.example 复制到 exe 旁，
  队友改知识库/提示词/放密钥无需重新打包（paths.py 在冻结态以 exe 目录为根）。
- --windowed 无黑框；--collect-all webview 收集其 JS 资源。
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "CodeAudit"
OUT = ROOT / "dist" / NAME

DATA_DIRS = ["knowledge", "prompts", "web"]
DATA_FILES = [".env.example"]


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd[:6]), "…")
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        sys.exit(f"打包失败 exit={r.returncode}")


def main() -> None:
    # 1) PyInstaller onedir（先清旧产物）
    spec = ROOT / "build" / f"{NAME}.spec"
    if OUT.exists():
        shutil.rmtree(OUT)
    # PDF 导出用的 pymupdf 会被 hook 顺带拖进 scipy/onnxruntime/matplotlib
    # 等无关重型依赖（实测多占 ~120MB），本工具用不到，显式排除。
    excludes = []
    for mod in ("scipy", "onnxruntime", "matplotlib", "pandas", "sympy",
                "IPython", "jupyter", "notebook", "pytest", "tkinter.test"):
        excludes += ["--exclude-module", mod]
    run([sys.executable, "-m", "PyInstaller",
         "--noconfirm", "--clean", "--onedir", "--windowed",
         "--name", NAME,
         "--collect-all", "webview",
         *excludes,
         "desktop.py"])
    if not OUT.exists():
        sys.exit(f"未找到产物目录 {OUT}")

    # 2) exe 旁组装可编辑数据
    for d in DATA_DIRS:
        dst = OUT / d
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(ROOT / d, dst,
                        ignore=shutil.ignore_patterns("__pycache__"))
    for f in DATA_FILES:
        src = ROOT / f
        if src.exists():
            shutil.copy(src, OUT / f)
    (OUT / "data").mkdir(exist_ok=True)

    # 3) 团队使用说明
    (OUT / "使用说明.txt").write_text(
        "明查秋毫 · 大模型代码审计系统 · 绿色版 v2\r\n"
        "==========================================\r\n\r\n"
        "1. 双击 CodeAudit.exe 打开窗口（首次启动约需几秒）\r\n"
        "2. 六个页签：审计 / 历史 / 知识库 / 规则库 / 设置 / MCP\r\n"
        "3. 静态检查免密钥、免费、秒级出报告；支持增量审计、任务取消、\r\n"
        "   报告导出 HTML/MD/JSON，完成任务自动存入历史（保留 50 次）\r\n"
        "4. AI 深度审计：在「设置」页在线填模型密钥/端点即可（保存到本文件夹\r\n"
        "   .env，密钥不回显明文）；也可手动把 .env.example 复制为 .env 填写\r\n"
        "5. 知识库/规则库页可在线新增自定义条目与正则规则（内置内容只读，\r\n"
        "   保护评测口径）；也可直接改 knowledge/ prompts/ 下的文件\r\n"
        "6. MCP 页：一键复制客户端配置，把审计能力接入 Claude Desktop/Cursor；\r\n"
        "   命令行方式：CodeAudit.exe --mcp（由客户端以管道拉起）\r\n"
        "7. 疑似误报可在代码行尾加  # noqa  或  # nosec  豁免，或在报告里点\r\n"
        "   「标记误报」进入反馈队列\r\n"
        "8. 右上角可切换深色/浅色主题；Ctrl+Enter 快捷开始审计\r\n"
        "9. 出问题先跑：CodeAudit.exe --selftest，看 selftest_result.txt\r\n\r\n"
        "若 Windows 弹「未知发布者」：更多选择 → 仍要运行（团队绿色版未做代码签名）\r\n\r\n"
        "⚠ 分发提醒：若本文件夹已放 .env（含密钥），拷给别人前必须删掉 .env，\r\n"
        "   或只拷 exe + _internal + knowledge + prompts + web，让对方各自建 .env\r\n",
        encoding="utf-8")

    size_mb = sum(f.stat().st_size for f in OUT.rglob("*")) / 1e6
    print(f"\n完成：{OUT}\n体积：约 {size_mb:.0f} MB\n"
          f"验收：{OUT / (NAME + '.exe')} --selftest")


if __name__ == "__main__":
    main()
