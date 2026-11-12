# -*- coding: utf-8 -*-
"""SARIF 2.1.0 导出（可选）：对接 GitHub Code Scanning / VS Code SARIF Viewer。

只做格式转换，不改变任何判定；严重度映射 critical|high→error、
medium→warning、low→note，规则 ID 与 CWE 以 tags 保留可溯源信息。
"""
from __future__ import annotations

import json
from pathlib import Path

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SEV_SCORE = {"critical": "9.0", "high": "7.0", "medium": "5.0", "low": "2.0"}


def _as_dict(rep) -> dict:
    if isinstance(rep, dict):
        return rep
    return json.loads(rep.to_json())


def to_sarif(rep, root=None, tool_name="明查秋毫 codeaudit",
             version="1.0.0") -> dict:
    doc = _as_dict(rep)
    issues = doc.get("issues", [])
    base = Path(root).resolve() if root else None
    rules, rule_idx = [], {}
    results = []
    for it in issues:
        rid = it.get("rule_id", "UNKNOWN")
        sev = it.get("severity", "medium")
        if rid not in rule_idx:
            rule_idx[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": rid.replace("-", ""),
                "shortDescription": {"text": it.get("title", rid)},
                "fullDescription": {"text": (it.get("analysis")
                                             or it.get("title") or rid)[:2000]},
                "defaultConfiguration": {"level": _LEVEL.get(sev, "warning")},
                "properties": {
                    "tags": [t for t in [it.get("category", ""), rid] if t],
                    "security-severity": _SEV_SCORE.get(sev, "5.0")},
            })
        uri = it.get("path", "")
        if base:
            try:
                uri = Path(uri).resolve().relative_to(base).as_posix()
            except (ValueError, OSError):
                uri = Path(uri).name
        uri = str(uri).replace("\\", "/").lstrip("/")
        start = int(it.get("line_start", 1) or 1)
        end = int(it.get("line_end") or start)
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_idx[rid],
            "level": _LEVEL.get(sev, "warning"),
            "message": {"text": (it.get("title", "") + " — "
                                 + (it.get("analysis") or "")).strip(" —")[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, start),
                               "endLine": max(start, end)},
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": rid + ":" + uri + ":" + str(start)},
            "properties": {
                "severity": sev,
                "category": it.get("category", ""),
                "detector": it.get("detector", ""),
                "confidence": it.get("confidence", 0),
                "evidence": (it.get("evidence") or "")[:500],
                "fix": (it.get("fix") or "")[:1000],
                "source": it.get("source", ""),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name, "version": version,
                "informationUri": "https://github.com/YUNMENGD/llm-code-audit",
                "rules": rules}},
            "results": results,
            "automationDetails": {
                "id": "codeaudit/" + str(doc.get("target", "")).replace("\\", "/")},
        }],
    }


def write_sarif(rep, out_path, root=None) -> dict:
    doc = to_sarif(rep, root=root)
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"ok": True, "path": str(p), "results": len(doc["runs"][0]["results"])}
