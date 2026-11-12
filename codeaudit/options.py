# -*- coding: utf-8 -*-
"""可选审计配置：扫描范围 / 预设 / 规则开关 / 严重度阈值 / 功能旗标。

默认口径与历史完全一致：全量预设、全部规则启用、低危可见、忽略规则温和。
所有增强项都是显式开启才生效，评测基线（bench-real）不因可选功能漂移。
"""
from __future__ import annotations

import fnmatch
import json
import os
import threading
from pathlib import Path

from .models import AuditReport, Severity
from .paths import DATA_DIR

CONFIG_DIR = DATA_DIR / "config"
OPTIONS_FILE = CONFIG_DIR / "options.json"
IGNORE_NAME = ".auditignore"
_LOCK = threading.Lock()

PRESETS = {
    "full": {"label": "全量（默认）", "categories": None},
    "security": {"label": "安全专项", "categories": {"security"}},
    "quality": {"label": "代码质量", "categories": {"logic", "style", "engineering"}},
}
SEV_ORDER = [s.value for s in Severity]        # critical → low
_ALWAYS_SKIP = {".git", "__pycache__"}
DEFAULT_IGNORE = ["*/node_modules/*", "*/.venv/*", "*/venv/*", "*/build/*",
                  "*/dist/*", "*/site-packages/*", "*/.tox/*"]

_DEFAULTS = {
    "preset": "full",
    "min_severity": "low",
    "entropy": False,
    "static_cache": False,
    "notify": False,
    "webhook": "",
    "use_ignore": True,
    "disabled_rules": [],
}
_KEYS = set(_DEFAULTS)


def load_options() -> dict:
    out = dict(_DEFAULTS)
    try:
        raw = json.loads(OPTIONS_FILE.read_text(encoding="utf-8"))
        for k, v in raw.items():
            if k in _KEYS:
                out[k] = v
    except (OSError, json.JSONDecodeError):
        pass
    if os.getenv("AUDIT_ENTROPY", "") == "1":
        out["entropy"] = True
    if os.getenv("AUDIT_STATIC_CACHE", "") == "1":
        out["static_cache"] = True
    if os.getenv("AUDIT_PRESET", "") in PRESETS:
        out["preset"] = os.getenv("AUDIT_PRESET")
    if os.getenv("AUDIT_MIN_SEVERITY", "") in SEV_ORDER:
        out["min_severity"] = os.getenv("AUDIT_MIN_SEVERITY")
    if os.getenv("AUDIT_NOTIFY", "") == "1":
        out["notify"] = True
    if os.getenv("AUDIT_WEBHOOK", ""):
        out["webhook"] = os.getenv("AUDIT_WEBHOOK", "")
    out["disabled_rules"] = [str(x) for x in (out.get("disabled_rules") or [])]
    return out


def save_options(updates: dict) -> dict:
    with _LOCK:
        cur = {}
        try:
            cur = json.loads(OPTIONS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            cur = {}
        for k, v in (updates or {}).items():
            if k not in _KEYS:
                raise ValueError("未知选项：" + str(k))
            if k == "preset" and v not in PRESETS:
                raise ValueError("预设必须是 full/security/quality")
            if k == "min_severity" and v not in SEV_ORDER:
                raise ValueError("严重度阈值必须是 critical/high/medium/low")
            if k == "disabled_rules":
                v = [str(x) for x in (v or [])]
            if k == "webhook" and v and not str(v).startswith(("http://", "https://")):
                raise ValueError("webhook 必须以 http:// 或 https:// 开头")
            cur[k] = v
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = OPTIONS_FILE.with_name(OPTIONS_FILE.name + ".tmp")
        tmp.write_text(json.dumps(cur, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(OPTIONS_FILE)
    return load_options()


def set_rule_switch(rule_id: str, enabled: bool) -> dict:
    opts = load_options()
    dis = set(opts["disabled_rules"])
    if enabled:
        dis.discard(rule_id)
    else:
        dis.add(rule_id)
    return save_options({"disabled_rules": sorted(dis)})


def filter_rules(rules: list, preset: str | None = None, disabled=None) -> list:
    """按预设类别 + 规则开关过滤；full 且无停用时原样返回（口径不变）。"""
    opts = load_options()
    preset = preset or opts["preset"]
    cats = (PRESETS.get(preset) or PRESETS["full"])["categories"]
    dis = set(disabled if disabled is not None else opts["disabled_rules"])
    out = []
    for r in rules:
        if r.get("id") in dis:
            continue
        if cats is not None and r.get("category") not in cats:
            continue
        out.append(r)
    return out


def sev_ok(sev: str, threshold: str | None) -> bool:
    if not threshold or threshold == "low":
        return True
    try:
        return SEV_ORDER.index(sev) <= SEV_ORDER.index(threshold)
    except ValueError:
        return True


def filter_report(rep: AuditReport, min_severity: str | None = None) -> AuditReport:
    """按严重度阈值裁剪报告并重算统计（不改原对象）。"""
    thr = min_severity or load_options()["min_severity"]
    if not thr or thr == "low":
        return rep
    kept = [i for i in rep.issues if sev_ok(i.severity.value, thr)]
    out = AuditReport(target=rep.target, issues=kept,
                      engine=dict(rep.engine), stats=dict(rep.stats))
    out.engine["min_severity"] = thr
    out.stats.update({"total": len(kept),
                      "by_severity": out.count_by("severity"),
                      "by_category": out.count_by("category"),
                      "by_detector": out.count_by("detector"),
                      "filtered_by_severity": len(rep.issues) - len(kept)})
    return out


def ignore_patterns(root: Path) -> list:
    pats = list(DEFAULT_IGNORE)
    f = Path(root) / IGNORE_NAME
    try:
        for ln in f.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if s and not s.startswith("#"):
                pats.append(s)
    except OSError:
        pass
    return pats


def is_ignored(path: Path, root: Path, patterns: list) -> bool:
    try:
        rel = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        rel = Path(path).name
    cands = (rel, "/" + rel)
    for pat in patterns:
        p = pat.rstrip("/")
        for c in cands:
            if fnmatch.fnmatch(c, pat) or fnmatch.fnmatch(c, p + "/*") \
                    or fnmatch.fnmatch(c, "*/" + p + "/*") or fnmatch.fnmatch(c, p):
                return True
    return False


def collect_files(target, exts, use_ignore: bool = True) -> list:
    """收集待扫文件（尊重 .auditignore 与内置排除）。"""
    tp = Path(target)
    if tp.is_file():
        return [tp]
    pats = ignore_patterns(tp) if use_ignore else []
    out = []
    for p in sorted(tp.rglob("*")):
        if not p.is_file() or p.suffix not in exts:
            continue
        if any(x in _ALWAYS_SKIP for x in p.parts):
            continue
        if use_ignore and is_ignored(p, tp, pats):
            continue
        out.append(p)
    return out


def read_ignore_text(root) -> str:
    try:
        return (Path(root) / IGNORE_NAME).read_text(encoding="utf-8")
    except OSError:
        return ""


def write_ignore_text(root, text: str) -> dict:
    f = Path(root) / IGNORE_NAME
    f.write_text(text or "", encoding="utf-8")
    return {"ok": True, "path": str(f)}
