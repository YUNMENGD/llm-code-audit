# -*- coding: utf-8 -*-
"""知识库与规则库在线管理（设置中心的「知识库配置」）。

原则：
- 内置弹药（knowledge/defects、knowledge/rules 原有文件）只读，评测口径
  依赖它们保持稳定；界面新增/修改一律写 custom 文件，随仓库分发、可评审；
- 知识条目改完即生效（load_knowledge 每次全量读盘）；向量索引需重建，
  提供 reindex() 一键清缓存（内存 + data/vec 派生物，删了可再生）；
- 自定义规则写入即被 load_rules() 纳入静态引擎，保存前强制正则编译校验。
"""
from __future__ import annotations

import json
import re
import shutil
import threading
from pathlib import Path

from . import retriever as R
from . import rules as RL
from .paths import KNOWLEDGE_DIR, RULES_DIR

CUSTOM_KB_FILE = KNOWLEDGE_DIR / "custom.json"
CUSTOM_RULES_FILE = RULES_DIR / "custom_rules.json"
_LOCK = threading.Lock()

_SEVS = ("critical", "high", "medium", "low")
_CATS = ("security", "logic", "style", "engineering")
_ID_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{1,63}$")


def _read_items(path: Path) -> list[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("items", [])
    except (OSError, json.JSONDecodeError):
        return []


def _write_custom(path: Path, key: str, rows: list[dict], name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"meta": {"name": name, "version": "1.0",
                    "note": "界面在线维护的自定义条目；内置文件保持只读，便于评测口径稳定。",
                    "maintainer": "web-ui"},
           key: rows}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def list_items() -> list[dict]:
    """全量知识条目，附来源文件与是否内置（内置不可删改）。"""
    out: list[dict] = []
    if not KNOWLEDGE_DIR.exists():
        return out
    for f in sorted(KNOWLEDGE_DIR.glob("*.json")):
        custom = f.name == CUSTOM_KB_FILE.name
        for it in _read_items(f):
            d = dict(it)
            d["_file"] = f.name
            d["_builtin"] = not custom
            out.append(d)
    return out


def save_item(item: dict) -> tuple[dict, bool]:
    """新增或更新自定义条目；同 id 内置条目禁止覆盖。返回 (条目, 是否新建)。"""
    iid = str(item.get("id", "")).strip()
    title = str(item.get("title", "")).strip()
    if not _ID_RX.match(iid):
        raise ValueError("ID 需为 2~64 位字母/数字/下划线/点/横线，如 CWE-1234")
    if not title:
        raise ValueError("标题不能为空")
    sev = str(item.get("severity", "medium")).lower()
    cat = str(item.get("category", "security")).lower()
    if sev not in _SEVS:
        raise ValueError("严重度必须是 critical/high/medium/low")
    if cat not in _CATS:
        raise ValueError("类别必须是 security/logic/style/engineering")
    clean = {"id": iid, "title": title, "category": cat, "severity": sev,
             "tags": [str(t) for t in (item.get("tags") or [])],
             "triggers": [str(t) for t in (item.get("triggers") or [])],
             "pattern": str(item.get("pattern", "")),
             "impact": str(item.get("impact", "")),
             "fix": str(item.get("fix", "")),
             "source": str(item.get("source", ""))}
    with _LOCK:
        for it in list_items():
            if it["id"] == iid and it["_builtin"]:
                raise ValueError(f"{iid} 是内置条目，不可覆盖；请换一个 ID")
        rows = _read_items(CUSTOM_KB_FILE)
        created = True
        for i, r in enumerate(rows):
            if r.get("id") == iid:
                rows[i] = clean
                created = False
                break
        if created:
            rows.append(clean)
        _write_custom(CUSTOM_KB_FILE, "items", rows, "自定义缺陷知识条目")
    return clean, created


def delete_item(item_id: str) -> None:
    with _LOCK:
        rows = _read_items(CUSTOM_KB_FILE)
        keep = [r for r in rows if r.get("id") != item_id]
        if len(keep) == len(rows):
            raise ValueError("只能删除自定义条目（内置条目受评测口径保护）")
        _write_custom(CUSTOM_KB_FILE, "items", keep, "自定义缺陷知识条目")


def reindex() -> dict:
    """清空向量缓存（内存 + 磁盘派生物），下次检索自动重建。"""
    removed = 0
    vec_dir = R.DATA_VEC
    if vec_dir.exists():
        for f in vec_dir.glob("kb_*.npz"):
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
    with R._KB_LOCK:
        R._KB.update(hash=None, ids=None, mat=None)
    return {"ok": True, "removed": removed,
            "note": "向量缓存已清空；配置了向量端点时下次检索自动重建，否则走关键词检索"}


# ---------- 规则库 ----------

def _read_rules(path: Path) -> list[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("rules", [])
    except (OSError, json.JSONDecodeError):
        return []


def list_rules() -> list[dict]:
    out: list[dict] = []
    if not RULES_DIR.exists():
        return out
    for f in sorted(RULES_DIR.glob("*.json")):
        if f.name == "js_rules.json":
            continue          # JS 弹药独立管理，不进 Python 规则管理页
        custom = f.name == CUSTOM_RULES_FILE.name
        for r in _read_rules(f):
            d = dict(r)
            d["_file"] = f.name
            d["_builtin"] = not custom
            out.append(d)
    return out


def save_rule(rule: dict) -> tuple[dict, bool]:
    rid = str(rule.get("id", "")).strip()
    title = str(rule.get("title", "")).strip()
    pattern = str(rule.get("pattern", ""))
    if not _ID_RX.match(rid):
        raise ValueError("ID 需为 2~64 位字母/数字/下划线/点/横线，如 R-CUSTOM-001")
    if not title:
        raise ValueError("标题不能为空")
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"正则不合法：{e}")
    if not pattern:
        raise ValueError("匹配正则不能为空")
    sev = str(rule.get("severity", "medium")).lower()
    cat = str(rule.get("category", "security")).lower()
    if sev not in _SEVS or cat not in _CATS:
        raise ValueError("严重度/类别取值不合法")
    clean = {"id": rid, "title": title, "category": cat, "severity": sev,
             "source": str(rule.get("source", "")), "pattern": pattern,
             "exclude": [str(x) for x in (rule.get("exclude") or [])],
             "why": str(rule.get("why", "")),
             "impact": str(rule.get("impact", "")),
             "suggestion": str(rule.get("suggestion", ""))}
    with _LOCK:
        for r in list_rules():
            if r["id"] == rid and r["_builtin"]:
                raise ValueError(f"{rid} 是内置规则，不可覆盖；请换一个 ID")
        rows = _read_rules(CUSTOM_RULES_FILE)
        created = True
        for i, r in enumerate(rows):
            if r.get("id") == rid:
                rows[i] = clean
                created = False
                break
        if created:
            rows.append(clean)
        _write_custom(CUSTOM_RULES_FILE, "rules", rows, "自定义硬性规则")
    return clean, created


def delete_rule(rule_id: str) -> None:
    with _LOCK:
        rows = _read_rules(CUSTOM_RULES_FILE)
        keep = [r for r in rows if r.get("id") != rule_id]
        if len(keep) == len(rows):
            raise ValueError("只能删除自定义规则（内置规则受评测口径保护）")
        _write_custom(CUSTOM_RULES_FILE, "rules", keep, "自定义硬性规则")


def test_pattern(pattern: str, sample: str) -> list[dict]:
    """对样例行试跑正则，返回命中行（保存前预览，防写坏规则）。"""
    try:
        rx = re.compile(pattern)
    except re.error as e:
        raise ValueError(f"正则不合法：{e}")
    hits = []
    for i, ln in enumerate(sample.splitlines(), 1):
        m = rx.search(ln)
        if m:
            hits.append({"line": i, "text": ln.strip()[:120],
                         "match": m.group(0)[:60]})
    return hits[:20]
