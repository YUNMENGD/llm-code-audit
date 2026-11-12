# -*- coding: utf-8 -*-
"""依赖漏洞扫描（可选模块）：对接 pip-audit / npm audit 查已知 CVE。

显式开启才运行，且只调用本机已安装的官方工具；工具缺失时如实返回不可用，
绝不编造漏洞数据。runner 参数供离线测试注入假结果。
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import Category, Issue, Severity

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "moderate": Severity.MEDIUM, "medium": Severity.MEDIUM,
            "low": Severity.LOW}


def detect_manifests(target) -> list:
    tp = Path(target)
    root = tp if tp.is_dir() else tp.parent
    out = []
    for name in ("requirements.txt", "pyproject.toml", "package.json"):
        f = root / name
        if f.exists():
            out.append(f)
    return out


def _run(cmd, cwd, timeout):
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def scan(target, runner=None, timeout: int = 180) -> dict:
    tp = Path(target)
    root = tp if tp.is_dir() else tp.parent
    manifests = detect_manifests(root)
    if not manifests:
        return {"ok": False, "issues": [], "tools": [],
                "note": "未找到 requirements.txt / pyproject.toml / package.json"}
    runner = runner or _run
    issues, tools, notes = [], [], []
    req = root / "requirements.txt"
    if req.exists():
        if shutil.which("pip-audit"):
            tools.append("pip-audit")
            raw = runner(["pip-audit", "-r", str(req), "-f", "json",
                          "--progress-spinner", "off"], root, timeout)
            try:
                data = json.loads(raw or "{}")
            except json.JSONDecodeError:
                data = {}
            deps = data.get("dependencies", data if isinstance(data, list) else [])
            for d in deps or []:
                for v in d.get("vulns", []) or []:
                    vid = v.get("id", "CVE-?")
                    issues.append(Issue(
                        rule_id="DEP-" + vid, category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="依赖 %s 存在已知漏洞 %s" % (d.get("name", "?"), vid),
                        path=str(req), line_start=1,
                        evidence="%s==%s" % (d.get("name", "?"), d.get("version", "?")),
                        analysis=(v.get("description") or "")[:800],
                        impact="已知 CVE 可被公开利用手法攻击。",
                        fix="升级到修复版本：%s" % (
                            ", ".join(v.get("fix_versions", []) or []) or "见公告"),
                        confidence=0.95, source="pip-audit / " + vid,
                        detector="static", verified=True))
        else:
            notes.append("pip-audit 未安装（pip install pip-audit 后可用）")
    pkg = root / "package.json"
    if pkg.exists():
        if shutil.which("npm"):
            tools.append("npm audit")
            raw = runner(["npm", "audit", "--json"], root, timeout)
            try:
                data = json.loads(raw or "{}")
            except json.JSONDecodeError:
                data = {}
            for name, v in (data.get("vulnerabilities") or {}).items():
                sev = _SEV_MAP.get(str(v.get("severity", "medium")).lower(),
                                   Severity.MEDIUM)
                issues.append(Issue(
                    rule_id="DEP-NPM-" + name, category=Category.SECURITY,
                    severity=sev,
                    title="npm 依赖 %s 存在已知漏洞" % name,
                    path=str(pkg), line_start=1, evidence=name,
                    analysis=json.dumps(v.get("via", []), ensure_ascii=False)[:800],
                    impact="已知漏洞可被公开利用手法攻击。",
                    fix="npm audit fix 或升级到修复版本。",
                    confidence=0.95, source="npm audit", detector="static",
                    verified=True))
        else:
            notes.append("npm 未安装")
    return {"ok": bool(tools), "issues": issues, "tools": tools,
            "manifests": [str(m) for m in manifests], "note": "；".join(notes)}
