# -*- coding: utf-8 -*-
"""误报反馈队列（G）：报告里"标记误报"→ 本地结构化队列 → 聚合为候选豁免规则。

数据飞轮闭环的存储层。约定：
  · 队列落 data/feedback/queue.json（append-only，键去重计数）
  · 键 = (rule, file基名, title)——同一条告警反复标记只涨计数不重复记
  · 本模块只攒数据不做判断：升格为 knowledge/guards 条目必须经
    tools/promote_feedback.py 聚合 + 人工确认 + bench-real 回测验证，
    与"每条豁免必须有可复核证据"的项目纪律一致。
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from .paths import DATA_DIR

QUEUE = DATA_DIR / "feedback" / "queue.json"
_LOCK = threading.Lock()


def _load() -> list[dict]:
    if QUEUE.exists():
        try:
            return json.loads(QUEUE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
    return []


def add(entry: dict) -> dict:
    """追加一条误报反馈。entry 需含 rule/title，可含 path/line/detector/evidence。

    返回落库后的记录（含累计次数与首次/最近时间戳）。
    """
    rule = str(entry.get("rule") or "").strip()
    title = str(entry.get("title") or "").strip()
    if not rule or not title:
        raise ValueError("反馈必须包含 rule 与 title")
    key = f"{rule}|{Path(str(entry.get('path') or '')).name}|{title}"
    now = _now()
    with _LOCK:
        rows = _load()
        for r in rows:
            if r["key"] == key:
                r["count"] += 1
                r["last"] = now
                r["last_entry"] = _clean(entry)
                _save(rows)
                return r
        rec = {"key": key, "count": 1, "first": now, "last": now,
               "rule": rule, "title": title, "path": entry.get("path", ""),
               "line": entry.get("line"), "detector": entry.get("detector", ""),
               "evidence": _clean(entry).get("evidence", "")}
        rows.append(rec)
        _save(rows)
        return rec


def add_many(entries: list[dict]) -> int:
    return sum(1 for e in entries if add(e))


def all_rows() -> list[dict]:
    return _load()


def stats() -> dict:
    rows = _load()
    return {"records": len(rows), "total_marks": sum(r.get("count", 1) for r in rows),
            "by_rule": dict(sorted(_rule_counts(rows).items(),
                                   key=lambda x: -x[1]))}


def _rule_counts(rows: list[dict]) -> dict[str, int]:
    c: dict[str, int] = {}
    for r in rows:
        c[r["rule"]] = c.get(r["rule"], 0) + r.get("count", 1)
    return c


def _clean(entry: dict) -> dict:
    return {k: str(v)[:200] if isinstance(v, str) else v
            for k, v in entry.items() if k in ("path", "line", "detector", "evidence")}


def _save(rows: list[dict]) -> None:
    QUEUE.parent.mkdir(parents=True, exist_ok=True)
    QUEUE.write_text(json.dumps(rows, ensure_ascii=False, indent=1),
                     encoding="utf-8")


def _now() -> str:
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")
