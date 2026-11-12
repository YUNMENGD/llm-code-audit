# -*- coding: utf-8 -*-
"""静态扫描缓存（可选）：按「文件内容哈希 + 规则指纹」复用上次结果。

默认关闭（--static-cache / AUDIT_STATIC_CACHE=1 显式开启）。规则库任何改动
都会改变指纹使缓存整体失效，因此不会出现「改了规则却读旧结果」的口径漂移。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from .models import Issue
from .paths import DATA_DIR

CACHE_FILE = DATA_DIR / "cache" / "static_scan.json"
_LOCK = threading.Lock()
_MEM: dict | None = None
_DIRTY = False


def enabled(explicit=None) -> bool:
    if explicit is not None:
        return bool(explicit)
    return os.getenv("AUDIT_STATIC_CACHE", "0") == "1"


def fingerprint(rules: list) -> str:
    keys = ("id", "pattern", "exclude", "severity", "category", "skip_path_rx",
            "top_only", "body_check", "probe_check", "logged_check",
            "resource_check", "match_comment", "case_insensitive", "exts")
    blob = json.dumps([{k: r.get(k) for k in keys} for r in rules],
                      ensure_ascii=False, sort_keys=True)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def _load() -> dict:
    global _MEM
    if _MEM is None:
        try:
            _MEM = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _MEM = {}
    return _MEM


def _key(path, fp: str) -> str:
    h = hashlib.sha1(Path(path).read_bytes()).hexdigest()
    return fp + ":" + h


def get(path, fp: str):
    try:
        return _load().get(_key(path, fp))
    except OSError:
        return None


def put(path, fp: str, rows: list) -> None:
    global _DIRTY
    try:
        with _LOCK:
            _load()[_key(path, fp)] = rows
            _DIRTY = True
    except OSError:
        pass


def flush() -> dict:
    global _DIRTY
    with _LOCK:
        if not _DIRTY or _MEM is None:
            return {"written": 0}
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_name(CACHE_FILE.name + ".tmp")
        tmp.write_text(json.dumps(_MEM, ensure_ascii=False), encoding="utf-8")
        tmp.replace(CACHE_FILE)
        _DIRTY = False
        return {"written": len(_MEM)}


def clear() -> dict:
    global _MEM, _DIRTY
    with _LOCK:
        _MEM = {}
        _DIRTY = False
        try:
            CACHE_FILE.unlink()
        except OSError:
            pass
    return {"ok": True}


def rows_to_issues(rows: list) -> list:
    out = []
    for d in rows or []:
        it = Issue.from_dict(d, path=d.get("path", ""),
                             detector=d.get("detector", "static"))
        it.verified = bool(d.get("verified", True))
        it.confidence = float(d.get("confidence", 0.95))
        out.append(it)
    return out
