# -*- coding: utf-8 -*-
"""审计历史：完成任务自动存档到 data/history/，可回看、可删除。

- 每次审计完成存一份完整 JSON（问题明细 + 引擎信息 + 统计）；
- 只保留最近 MAX_KEEP 份，超出自动淘汰最旧（派生物，可随时重建）；
- 回看时把 JSON 还原成 AuditReport，复用现有交互报告渲染器。
"""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

from .models import AuditReport, Issue
from .paths import DATA_DIR

HIST_DIR = DATA_DIR / "history"
MAX_KEEP = 50
_ID_RX = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")


def _path(hist_id: str) -> Path:
    if not _ID_RX.match(hist_id or ""):
        raise ValueError("非法历史记录 ID")
    return HIST_DIR / f"{hist_id}.json"


def save(rep: AuditReport, meta: dict | None = None) -> str:
    """存档一次审计结果，返回历史 ID。"""
    HIST_DIR.mkdir(parents=True, exist_ok=True)
    hist_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    meta = meta or {}
    doc = {
        "id": hist_id,
        "ts": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": rep.target,
        "mode": meta.get("mode", ""),
        "depth": meta.get("depth", ""),
        "engine": rep.engine,
        "stats": rep.stats,
        "issues": [i.to_dict() for i in rep.sorted_issues()],
    }
    _path(hist_id).write_text(json.dumps(doc, ensure_ascii=False, indent=1),
                              encoding="utf-8")
    _prune()
    return hist_id


def _prune() -> None:
    files = sorted(HIST_DIR.glob("*.json"))
    for f in files[:max(0, len(files) - MAX_KEEP)]:
        try:
            f.unlink()
        except OSError:
            pass


def list_history(limit: int = 50) -> list[dict]:
    """按时间倒序返回摘要（不含问题明细，列表页轻量）。"""
    if not HIST_DIR.exists():
        return []
    rows: list[dict] = []
    for f in sorted(HIST_DIR.glob("*.json"), reverse=True)[:limit]:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows.append({
            "id": d.get("id", f.stem),
            "time_str": d.get("time_str", ""),
            "target": d.get("target", ""),
            "mode": d.get("mode", ""),
            "depth": d.get("depth", ""),
            "total": (d.get("stats") or {}).get("total", 0),
            "by_severity": (d.get("stats") or {}).get("by_severity", {}),
            "model": (d.get("engine") or {}).get("model", ""),
        })
    return rows


def load_report(hist_id: str) -> AuditReport:
    """把存档 JSON 还原为 AuditReport（含 verified/votes/models 等字段）。"""
    raw = json.loads(_path(hist_id).read_text(encoding="utf-8"))
    issues: list[Issue] = []
    for d in raw.get("issues", []):
        it = Issue.from_dict(d, path=d.get("path", ""),
                             detector=d.get("detector", "llm"))
        it.verified = bool(d.get("verified", False))
        it.votes = int(d.get("votes", 1) or 1)
        it.models = list(d.get("models") or [])
        issues.append(it)
    return AuditReport(target=raw.get("target", ""), issues=issues,
                       engine=raw.get("engine") or {},
                       stats=raw.get("stats") or {})


def delete(hist_id: str) -> None:
    p = _path(hist_id)
    if not p.exists():
        raise FileNotFoundError("历史记录不存在")
    p.unlink()
