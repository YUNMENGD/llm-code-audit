"""增量审计缓存（D17）。

键 = sha256(模型名 + 完整渲染后的 Prompt)。Prompt 含代码、检索到的知识、
few-shot、模板本体——任何一处变化都会自然 miss，无需手写版本号。
值 = 模型原始输出文本（解析/校验逻辑不进缓存，代码升级后旧缓存仍安全重放）。

data/cache/audit_cache.json 属派生数据，gitignore 已覆盖；删了只是重新花额度。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
CACHE_FILE = _ROOT / "data" / "cache" / "audit_cache.json"
_MAX_ENTRIES = 4000
_PRUNE_TO = 3000

_LOCK = threading.Lock()
_MEM: dict | None = None


def enabled(flag: bool | None = None) -> bool:
    """显式参数 > 环境变量 AUDIT_CACHE > 默认开。"""
    if flag is not None:
        return flag
    return os.getenv("AUDIT_CACHE", "1") != "0"


def cache_key(prompt: str, model: str) -> str:
    return hashlib.sha256(
        (model + "\x00" + prompt).encode("utf-8")).hexdigest()[:32]


def _load() -> dict:
    global _MEM
    if _MEM is None:
        try:
            _MEM = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if not isinstance(_MEM.get("entries"), dict):
                raise ValueError
        except (OSError, ValueError):
            _MEM = {"version": 1, "entries": {}}
    return _MEM


def get(key: str) -> str | None:
    with _LOCK:
        ent = _load()["entries"].get(key)
        return ent.get("raw") if ent else None


def put(key: str, raw: str, *, model: str = "") -> None:
    with _LOCK:
        d = _load()
        d["entries"][key] = {"raw": raw, "ts": int(time.time()), "model": model}
        if len(d["entries"]) > _MAX_ENTRIES:      # LRU 近似：按时间戳保留新的
            d["entries"] = dict(sorted(
                d["entries"].items(), key=lambda kv: kv[1]["ts"])[-_PRUNE_TO:])


def flush() -> None:
    with _LOCK:
        d = _load()
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(
                json.dumps(d, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass


def stats() -> dict:
    with _LOCK:
        ents = _load()["entries"]
        return {"entries": len(ents),
                "by_model": _count(ents, "model")}


def _count(ents: dict, field: str) -> dict:
    out: dict[str, int] = {}
    for e in ents.values():
        k = str(e.get(field, ""))
        out[k] = out.get(k, 0) + 1
    return out
