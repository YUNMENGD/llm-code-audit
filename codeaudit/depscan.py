# -*- coding: utf-8 -*-
"""依赖漏洞扫描（可选模块）：对接 pip-audit / npm audit 查已知 CVE。

显式开启才运行，且只调用本机已安装的官方工具；工具缺失时如实返回不可用，
绝不编造漏洞数据。runner 参数供离线测试注入假结果。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .models import Category, Issue, Severity

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "moderate": Severity.MEDIUM, "medium": Severity.MEDIUM,
            "low": Severity.LOW}


def find_pip_audit() -> list[str] | None:
    """解析 pip-audit 调用命令：显式配置 → 独立环境解释器 → 系统 PATH。

    优先「解释器 -m pip_audit」而非 Scripts/pip-audit.exe 包装器：
    包装器在受宿主注入 PYTHONPATH 的环境里可能加载到错误的 site-packages
    （实测出现 ModuleNotFoundError: packaging），模块方式由解释器自身
    决定搜索路径，更稳。返回值是命令前缀列表。
    """
    env = os.getenv("PIPAUDIT_BIN", "").strip()
    if env and Path(env).exists():
        p = Path(env)
        if p.name.lower().startswith("python"):
            return [str(p), "-m", "pip_audit"]
        # 指向 Scripts/pip-audit.exe 时，优先用同目录解释器
        py = p.parent / ("python.exe" if os.name == "nt" else "python")
        return [str(py), "-m", "pip_audit"] if py.exists() else [str(p)]
    for root in (Path("D:/tools/pip-audit"),
                 Path.home() / "tools" / "pip-audit"):
        py = root / "Scripts" / "python.exe" if os.name == "nt" \
            else root / "bin" / "python"
        if py.exists():
            return [str(py), "-m", "pip_audit"]
    found = shutil.which("pip-audit")
    return [found] if found else None


def _child_env() -> dict:
    """子进程环境：剔除宿主注入的 PYTHONPATH/PYTHONHOME，避免串到别的解释器。"""
    return {k: v for k, v in os.environ.items()
            if k not in ("PYTHONPATH", "PYTHONHOME")}


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
    """返回 (stdout, 诊断信息)。失败绝不静默：错误要能让上层如实告知。"""
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           env=_child_env())
        diag = ""
        if p.returncode not in (0, 1):     # pip-audit: 1=发现漏洞（正常）
            diag = f"退出码 {p.returncode}：{(p.stderr or '').strip()[-300:]}"
        elif not (p.stdout or "").strip():
            diag = "无输出：" + ((p.stderr or "").strip()[-300:] or "工具未产出结果")
        return p.stdout or "", diag
    except subprocess.TimeoutExpired:
        return "", f"扫描超时（>{timeout}s）"
    except OSError as e:
        return "", f"无法启动工具：{e}"


def _unpack(raw):
    """兼容 runner 只返回字符串（离线测试注入）与返回元组两种形态。"""
    if isinstance(raw, tuple):
        return raw[0], raw[1]
    return raw, ""


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
        pa_cmd = find_pip_audit()
        if pa_cmd:
            tools.append("pip-audit")
            # --no-deps：只审清单里锁定的版本，不去解析/构建依赖树
            # （默认模式需联网解析，失败时输出非 JSON，会被误当成「0 漏洞」）
            # 绝对路径：子进程 cwd 会切到清单所在目录，相对路径会解析错位
            # 导致工具读不到文件、输出为空却被当成「0 漏洞」（已实测）
            raw, diag = _unpack(runner([*pa_cmd, "-r", str(req.resolve()),
                                        "-f", "json", "--progress-spinner",
                                        "off", "--no-deps"], root, timeout))
            try:
                data = json.loads(raw) if raw.strip() else {}
                if not raw.strip():
                    notes.append("pip-audit 无任何输出，本次结果不可信"
                                 + ("：" + diag if diag else "（请检查清单格式）"))
            except json.JSONDecodeError:
                data = {}
                notes.append("pip-audit 输出无法解析，本次结果不可信"
                             + ("：" + diag if diag else ""))
            if diag:
                notes.append("pip-audit " + diag)
            deps = data.get("dependencies", data if isinstance(data, list) else [])
            seen = set()
            for d in deps or []:
                for v in d.get("vulns", []) or []:
                    vid = v.get("id", "CVE-?")
                    key = (d.get("name"), d.get("version"), vid)
                    if key in seen:            # 同一漏洞多条别名记录，去重
                        continue
                    seen.add(key)
                    aliases = [a for a in (v.get("aliases") or [])
                               if a.startswith("CVE-")]
                    show_id = aliases[0] if aliases else vid
                    issues.append(Issue(
                        rule_id="DEP-" + show_id, category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="依赖 %s %s 存在已知漏洞 %s" % (
                            d.get("name", "?"), d.get("version", "?"), show_id),
                        path=str(req), line_start=1,
                        evidence="%s==%s" % (d.get("name", "?"), d.get("version", "?")),
                        analysis=(v.get("description") or "")[:800],
                        impact="已知 CVE 可被公开利用手法攻击。",
                        fix="升级到修复版本：%s" % (
                            ", ".join(v.get("fix_versions", []) or []) or "见公告"),
                        confidence=0.95,
                        source="pip-audit / " + vid + (
                            " (" + ", ".join(aliases) + ")" if aliases else ""),
                        detector="static", verified=True))
        else:
            notes.append("pip-audit 未安装（pip install pip-audit，"
                         "或用 PIPAUDIT_BIN/设置页指定可执行文件路径）")
    pkg = root / "package.json"
    if pkg.exists():
        if shutil.which("npm"):
            tools.append("npm audit")
            raw, diag = _unpack(runner(["npm", "audit", "--json"], root, timeout))
            try:
                data = json.loads(raw or "{}")
            except json.JSONDecodeError:
                data = {}
                notes.append("npm audit 输出无法解析，本次结果不可信"
                             + ("：" + diag if diag else ""))
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
