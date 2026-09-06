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
    run([sys.executable, "-m", "PyInstaller",
         "--noconfirm", "--clean", "--onedir", "--windowed",
         "--name", NAME,
         "--collect-all", "webview",
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
        "大模型代码审计系统 · 绿色版\r\n"
        "========================\r\n\r\n"
        "1. 双击 CodeAudit.exe 打开窗口（首次启动约需几秒）\r\n"
        "2. 静态检查模式免密钥、免费、秒级出报告\r\n"
        "3. AI 深度审计：把 .env.example 复制为 .env，填入你的百炼/DeepSeek Key\r\n"
        "4. 知识库/规则/提示词就在本文件夹 knowledge/ prompts/ 下，\r\n"
        "   改完重启 exe 即生效，无需重新打包\r\n"
        "5. 疑似误报可在代码行尾加  # noqa  或  # nosec  豁免\r\n"
        "6. 出问题先跑：CodeAudit.exe --selftest，看 selftest_result.txt\r\n\r\n"
        "若 Windows 弹「未知发布者」：更多选择 → 仍要运行（团队绿色版未做代码签名）\r\n",
        encoding="utf-8")

    size_mb = sum(f.stat().st_size for f in OUT.rglob("*")) / 1e6
    print(f"\n完成：{OUT}\n体积：约 {size_mb:.0f} MB\n"
          f"验收：{OUT / (NAME + '.exe')} --selftest")


if __name__ == "__main__":
    main()
