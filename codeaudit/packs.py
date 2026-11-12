# -*- coding: utf-8 -*-
"""规则包 / 知识包导入导出（可选）：团队之间共享自定义弹药。

只搬运自定义条目；内置知识库与规则永不导出为可覆盖对象、也永不被导入覆盖
（复用 kbadmin 的内置只读保护与正则/枚举校验）。带校验和防篡改。
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import kbadmin as KA

PACK_KIND = "codeaudit-pack"
PACK_VERSION = 1


def _checksum(rules: list, items: list) -> str:
    blob = json.dumps({"r": rules, "i": items}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def export_pack(include_rules: bool = True, include_kb: bool = True) -> dict:
    rules = ([dict(r) for r in KA.list_rules() if not r.get("_builtin")]
             if include_rules else [])
    items = ([dict(i) for i in KA.list_items() if not i.get("_builtin")]
             if include_kb else [])
    for r in rules:
        r.pop("_file", None)
        r.pop("_builtin", None)
    for i in items:
        i.pop("_file", None)
        i.pop("_builtin", None)
    return {"pack": PACK_KIND, "version": PACK_VERSION,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rules": rules, "items": items,
            "checksum": _checksum(rules, items)}


def import_pack(pack: dict, dry_run: bool = False) -> dict:
    if not isinstance(pack, dict) or pack.get("pack") != PACK_KIND:
        raise ValueError("不是合法的 codeaudit 规则/知识包")
    rules = pack.get("rules") or []
    items = pack.get("items") or []
    if pack.get("checksum") and pack["checksum"] != _checksum(rules, items):
        raise ValueError("包校验和不匹配，内容可能被篡改")
    added, skipped = [], []
    for r in rules:
        rid = str(r.get("id", "?"))
        if dry_run:
            skipped.append({"id": rid, "kind": "rule", "reason": "dry-run 未写入"})
            continue
        try:
            KA.save_rule(r)
            added.append("rule:" + rid)
        except ValueError as e:
            skipped.append({"id": rid, "kind": "rule", "reason": str(e)[:120]})
    for i in items:
        iid = str(i.get("id", "?"))
        if dry_run:
            skipped.append({"id": iid, "kind": "kb", "reason": "dry-run 未写入"})
            continue
        try:
            KA.save_item(i)
            added.append("kb:" + iid)
        except ValueError as e:
            skipped.append({"id": iid, "kind": "kb", "reason": str(e)[:120]})
    return {"ok": True, "dry_run": dry_run, "added": added, "skipped": skipped,
            "added_count": len(added), "skipped_count": len(skipped)}


def write_pack(out_path, **kw) -> dict:
    pack = export_pack(**kw)
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(pack, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"ok": True, "path": str(p), "rules": len(pack["rules"]),
            "items": len(pack["items"])}
