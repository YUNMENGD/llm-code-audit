# -*- coding: utf-8 -*-
"""桌面应用启动器（F 项）+ 绿色版自检入口。

用法：
  python desktop.py              开发态运行
  CodeAudit.exe                  打包后双击运行（独立窗口）
  CodeAudit.exe --selftest       打包验收：起服务→调 API→写 selftest_result.txt 后退出
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

import uvicorn

import webapp
from codeaudit.paths import ROOT


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _serve(port: int) -> None:
    uvicorn.run(webapp.app, host="127.0.0.1", port=port, log_level="warning")


def _wait_ready(port: int, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _get(url: str, timeout: float = 15.0) -> dict:
    return json.loads(urllib.request.urlopen(url, timeout=timeout).read())


def _post(url: str, obj: dict, timeout: float = 20.0) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def _selftest(port: int) -> int:
    """端到端：/api/check → 写临时缺陷样例 → 静态审计 → 取报告。全绿才 PASS。"""
    url = f"http://127.0.0.1:{port}"
    lines: list[str] = []
    ok = True
    sample = ROOT / "selftest_sample.py"
    try:
        c = _get(url + "/api/check")
        lines.append(f"/api/check → 规则{c['rules']} 知识{c['knowledge']} "
                     f"LLM={'就绪' if c['llm_ready'] else '未配置'}")
        if c["rules"] == 0 or c["knowledge"] == 0:
            ok = False
            lines.append("knowledge/rules 未随 exe 分发")

        sample.write_text('import os\nos.system("rm -rf " + x)\n',
                          encoding="utf-8")
        jid = _post(url + "/api/audit",
                    {"target": str(sample), "mode": "static",
                     "depth": "file"})["job_id"]
        st: dict = {}
        for _ in range(60):
            time.sleep(0.4)
            st = _get(f"{url}/api/job/{jid}")
            if st["status"] != "running":
                break
        if st.get("status") != "done":
            ok = False
            lines.append(f"审计任务未完成：{st}")
        else:
            res = _get(f"{url}/api/result/{jid}")
            n = res["stats"]["total"]
            lines.append(f"静态审计 → 问题{n}条 html字符{len(res['html'])}")
            if n < 1:
                ok = False
                lines.append("已知缺陷样例应至少报 1 条")

        # AI 深度审计端到端（仅在 .env 配置了密钥时跑真实调用——验证冻结态下
        # .env 加载、调用图构建、LLM 请求全链路；无密钥环境 SKIP 不算失败）
        if c["llm_ready"]:
            jid2 = _post(url + "/api/audit",
                         {"target": str(sample), "mode": "ai",
                          "depth": "file"})["job_id"]
            st2: dict = {}
            for _ in range(150):
                time.sleep(0.8)
                st2 = _get(f"{url}/api/job/{jid2}")
                if st2["status"] != "running":
                    break
            if st2.get("status") != "done":
                ok = False
                lines.append(f"AI 审计未完成：{st2}")
            else:
                res2 = _get(f"{url}/api/result/{jid2}")
                n2 = res2["stats"]["total"]
                eng = res2.get("engine") or {}
                lines.append(f"AI 审计 → 问题{n2}条 模型={eng.get('model')}"
                             f" 调用图边数={eng.get('callgraph', {}).get('edges', 0)}")
                if n2 < 1:
                    ok = False
                    lines.append("AI 模式对已知缺陷样例应至少报 1 条")
        else:
            lines.append("AI 审计 → SKIP（未配置 LLM_API_KEY）")
    except Exception as e:                        # noqa: BLE001
        ok = False
        lines.append(f"{type(e).__name__}: {e}")
    finally:
        sample.unlink(missing_ok=True)
    out = ROOT / "selftest_result.txt"
    out.write_text(("PASS\n" if ok else "FAIL\n") + "\n".join(lines),
                   encoding="utf-8")
    print(("PASS " if ok else "FAIL ") + str(out))
    for ln in lines:
        print("   ", ln)
    return 0 if ok else 1


def main() -> None:
    # 打包成窗口程序（无控制台）后 sys.stdout 可能为 None，兜底防 print 报错
    if getattr(sys, "frozen", False) and sys.stdout is None:
        sys.stdout = sys.stderr = open(os.devnull, "w")

    port = _free_port()
    threading.Thread(target=_serve, args=(port,), daemon=True).start()
    if not _wait_ready(port):
        print("后端服务启动失败：端口或依赖异常")
        raise SystemExit(2)
    url = f"http://127.0.0.1:{port}"

    if "--selftest" in sys.argv:
        raise SystemExit(_selftest(port))

    try:
        import webview
        webview.create_window("大模型代码审计系统", url,
                              width=1200, height=800, min_size=(900, 600))
        webview.start()
    except Exception:                             # noqa: BLE001
        print(f"pywebview 不可用，已退化为浏览器模式：{url}")
        webbrowser.open(url)
        threading.Event().wait()                  # 保持服务存活


if __name__ == "__main__":
    main()
