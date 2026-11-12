# -*- coding: utf-8 -*-
"""完成通知（可选）：本机系统通知 + 用户显式配置的 webhook。

默认全部关闭。webhook 只有在用户显式填写 URL 后才发送，且只发审计摘要
（对象名/问题数/严重度分布），绝不发送源码、证据片段或密钥。
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request

_PS = (
    "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');"
    "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing');"
    "$n=New-Object System.Windows.Forms.NotifyIcon;"
    "$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;"
    "$n.ShowBalloonTip(5000,'{title}','{msg}',"
    "[System.Windows.Forms.ToolTipIcon]::Info);Start-Sleep -Milliseconds 5200;"
    "$n.Dispose()"
)


def _clean(s: str) -> str:
    return str(s).replace("'", "").replace('"', "").replace("\n", " ")[:180]


def system_notify(title: str, message: str) -> dict:
    if sys.platform != "win32":
        return {"ok": False, "note": "系统通知当前仅实现 Windows"}
    script = _PS.format(title=_clean(title), msg=_clean(message))
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", script],
                       capture_output=True, timeout=20)
        return {"ok": True}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "note": str(e)[:120]}


def summary_payload(rep_summary: dict) -> dict:
    """只含统计摘要，不含任何源码/证据/完整路径。"""
    return {
        "event": "audit_finished",
        "target_name": str(rep_summary.get("target_name", ""))[:120],
        "total": int(rep_summary.get("total", 0)),
        "by_severity": rep_summary.get("by_severity", {}),
        "mode": rep_summary.get("mode", ""),
        "elapsed_sec": rep_summary.get("elapsed_sec", 0),
    }


def webhook(url: str, payload: dict, timeout: int = 8) -> dict:
    if not url:
        return {"ok": False, "note": "未配置 webhook"}
    if not url.startswith(("http://", "https://")):
        return {"ok": False, "note": "webhook 协议不合法"}
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"ok": 200 <= r.status < 300, "status": r.status}
    except Exception as e:                                  # noqa: BLE001
        return {"ok": False, "note": str(e)[:160]}


def notify_done(rep_summary: dict, opts: dict) -> dict:
    out = {"system": None, "webhook": None}
    payload = summary_payload(rep_summary)
    if opts.get("notify"):
        out["system"] = system_notify(
            "代码审计完成",
            "对象 %s：共 %d 个问题" % (payload["target_name"], payload["total"]))
    if opts.get("webhook"):
        out["webhook"] = webhook(opts["webhook"], payload)
    return out
