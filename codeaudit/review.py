# -*- coding: utf-8 -*-
"""误报反馈评审 + 人工标注工具（数据飞轮的可操作闭环）。

评审：队列里每条误报标记可人工「采纳/驳回」；采纳只是确认误报，
真正写入知识库必须过零误杀回归闸门（apply_adopted 默认 dry_run）。
标注：把任意审计报告逐条摊开（带源码上下文），人工判 T/F/? 并落盘，
格式与 bench-real 兼容，便于后续扩基准。
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import feedback as FB
from . import kbadmin as KA
from .paths import DATA_DIR, ROOT

REVIEW_FILE = DATA_DIR / "feedback" / "review.json"
ANNOT_DIR = ROOT / "bench-annot"
_DECISIONS = ("pending", "adopt", "reject")


def _load_review() -> dict:
    try:
        return json.loads(REVIEW_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_review(d: dict) -> None:
    REVIEW_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = REVIEW_FILE.with_name(REVIEW_FILE.name + ".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(REVIEW_FILE)


def rows() -> list:
    rev = _load_review()
    out = []
    for r in FB.all_rows():
        k = r.get("key", "")
        st = rev.get(k, {})
        d = dict(r)
        d["decision"] = st.get("decision", "pending")
        d["note"] = st.get("note", "")
        d["reviewed_at"] = st.get("ts", "")
        out.append(d)
    return out


def set_decision(key: str, decision: str, note: str = "") -> dict:
    if decision not in _DECISIONS:
        raise ValueError("决定必须是 pending/adopt/reject")
    if not key:
        raise ValueError("缺少反馈键")
    rev = _load_review()
    rev[key] = {"decision": decision, "note": str(note)[:500],
                "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
    _save_review(rev)
    return {"ok": True, "key": key, "decision": decision}


def stats() -> dict:
    rs = rows()
    return {"total": len(rs),
            "pending": sum(1 for r in rs if r["decision"] == "pending"),
            "adopt": sum(1 for r in rs if r["decision"] == "adopt"),
            "reject": sum(1 for r in rs if r["decision"] == "reject")}


def _kid(rule: str, key: str) -> str:
    h = hashlib.sha1(str(key).encode("utf-8")).hexdigest()[:6]
    return "FP-" + rule + "-" + h


def _proposals() -> list:
    """把已采纳的误报转成知识条目提案（记录「何时不该报」的判定边界）。"""
    out = []
    for r in rows():
        if r["decision"] != "adopt":
            continue
        rule = str(r.get("rule", "UNKNOWN"))
        out.append({
            "id": _kid(rule, r.get("key", "")),
            "title": "误报边界：" + str(r.get("title", ""))[:60],
            "category": "logic", "severity": "low",
            "tags": ["false-positive", "boundary", rule],
            "triggers": [rule],
            "pattern": "规则 " + rule + " 在如下形态下属于误报，不应告警："
                       + str(r.get("evidence", ""))[:200],
            "impact": "误报会淹没真实缺陷，降低审计可信度。",
            "fix": "判定前先确认是否命中该边界形态；命中则不报。",
            "source": "人工评审确认（反馈键 " + str(r.get("key", ""))[:60] + "）",
        })
    return out


def apply_adopted(dry_run: bool = True, libs=None) -> dict:
    """零误杀闸门：先跑六库回归，任何真缺陷被误杀即拒绝写入知识库。"""
    from . import realeval as RE
    props = _proposals()
    if not props:
        return {"ok": False, "note": "没有已采纳的误报", "proposals": []}
    lost_total, checked = 0, []
    for lib in (libs or RE.LIBS):
        r = RE.evaluate(lib)
        if "error" in r:
            checked.append({"lib": lib, "skipped": r["error"]})
            continue
        lost = r["current"]["lost_T"]
        lost_total += lost
        checked.append({"lib": lib, "lost_T": lost,
                        "kept_T": r["current"]["kept_T"]})
    if lost_total:
        return {"ok": False, "blocked": "零误杀红线", "lost_T": lost_total,
                "regression": checked, "proposals": props}
    written = []
    if not dry_run:
        for p in props:
            try:
                KA.save_item(p)
                written.append(p["id"])
            except ValueError:
                pass
    return {"ok": True, "dry_run": dry_run, "regression": checked,
            "proposals": props, "written": written}


# ---------- 人工标注 ----------

def annotate_items(rep, context_lines: int = 5) -> list:
    issues = rep.sorted_issues() if hasattr(rep, "sorted_issues") else []
    out = []
    for n, it in enumerate(issues):
        try:
            lines = Path(it.path).read_text(encoding="utf-8",
                                            errors="replace").splitlines()
            lo = max(0, it.line_start - 1 - context_lines)
            hi = min(len(lines), it.line_start + context_lines)
            ctx = "\n".join("%d| %s" % (i + 1, lines[i]) for i in range(lo, hi))
        except OSError:
            ctx = "(源文件不可读)"
        out.append({"idx": n, "rule": it.rule_id, "title": it.title,
                    "severity": it.severity.value, "path": it.path,
                    "line": it.line_start, "evidence": it.evidence,
                    "detector": it.detector, "context": ctx, "verdict": "?"})
    return out


def save_annotations(name: str, items: list, verdicts: dict) -> dict:
    safe = "".join(c for c in str(name) if c.isalnum() or c in "-_")[:60] or "annot"
    ANNOT_DIR.mkdir(parents=True, exist_ok=True)
    anns = []
    for it in items:
        v = str(verdicts.get(str(it["idx"]), verdicts.get(it["idx"], "?")))
        if v not in ("T", "F", "?"):
            v = "?"
        anns.append({"file": Path(it["path"]).name, "line": it["line"],
                     "rule": it["rule"], "verdict": v,
                     "note": str(it.get("title", ""))[:120]})
    T = sum(1 for a in anns if a["verdict"] == "T")
    F = sum(1 for a in anns if a["verdict"] == "F")
    Q = sum(1 for a in anns if a["verdict"] == "?")
    doc = {"meta": {"name": safe, "annotated_at": time.strftime("%Y-%m-%d"),
                    "method": "内置标注工具人工核验 T/F/?",
                    "verdict_legend": "T=真缺陷 / F=误报 / ?=存疑（单列不计入 precision）"},
           "annotations": anns}
    f = ANNOT_DIR / (safe + ".json")
    f.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    prec = round(T / (T + F), 3) if (T + F) else None
    return {"ok": True, "path": str(f), "T": T, "F": F, "?": Q, "precision": prec}


def list_annotations() -> list:
    if not ANNOT_DIR.exists():
        return []
    out = []
    for f in sorted(ANNOT_DIR.glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        a = d.get("annotations", [])
        T = sum(1 for x in a if x.get("verdict") == "T")
        F = sum(1 for x in a if x.get("verdict") == "F")
        out.append({"name": f.stem, "count": len(a), "T": T, "F": F,
                    "precision": round(T / (T + F), 3) if (T + F) else None})
    return out
