# -*- coding: utf-8 -*-
"""桌面应用启动器（F 项）：独立窗口形态的代码审计工具。

用法：python desktop.py
- 自动挑选空闲端口启动本地服务（仅 127.0.0.1）
- pywebview 开独立窗口；若本机装不到 pywebview，自动退化为
  「浏览器模式」（打开默认浏览器访问同一服务），功能完全一致

静态检查模式全程免费；AI 模式需在 .env 配好 LLM_API_KEY。
"""
from __future__ import annotations

import socket
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

import webapp

HERE = Path(__file__).resolve().parent


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _serve(port: int) -> None:
    uvicorn.run(webapp.app, host="127.0.0.1", port=port,
                log_level="warning")


def main() -> None:
    import os
    if Path(".env").exists():
        from dotenv import load_dotenv
        load_dotenv(override=False)

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    threading.Thread(target=_serve, args=(port,), daemon=True).start()

    # 等服务就绪
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                break
        except OSError:
            time.sleep(0.1)

    try:
        import webview
        webview.create_window("大模型代码审计系统", url,
                              width=1200, height=800, min_size=(900, 600))
        webview.start()
    except Exception:                                   # noqa: BLE001
        print(f"pywebview 不可用，已退化为浏览器模式：{url}")
        webbrowser.open(url)
        threading.Event().wait()                        # 保持服务存活


if __name__ == "__main__":
    main()
