# -*- coding: utf-8 -*-
"""报告精简/详细切换 + PDF 导出（可选）。

精简：只给清单表 + 统计（适合汇报）；详细：完整证据/分析/修复（默认）。
PDF：优先用 PyMuPDF 直接生成（内置 CJK 字体），不可用时降级为
「打印版 HTML」——浏览器一键另存 PDF，如实告知，不假装生成成功。
"""
from __future__ import annotations

import html
from pathlib import Path

from .models import Severity

_LABEL = {Severity.CRITICAL: "严重", Severity.HIGH: "高危",
          Severity.MEDIUM: "中危", Severity.LOW: "低危"}


def render_brief_markdown(rep) -> str:
    s = rep.stats or {}
    lines = ["# 代码审计报告（精简版）", "",
             "- 审计对象：`%s`" % rep.target,
             "- 引擎：%s" % rep.engine.get("model", "?"),
             "- 问题总数：**%d**" % s.get("total", len(rep.issues)), ""]
    sv = s.get("by_severity") or {}
    if sv:
        lines += ["严重度分布：" + "，".join("%s %d" % (k, v) for k, v in sv.items()), ""]
    lines += ["| # | 级别 | 规则 | 位置 | 问题 |", "|---|---|---|---|---|"]
    for n, i in enumerate(rep.sorted_issues(), 1):
        lines.append("| %d | %s | %s | %s:%d | %s |" % (
            n, _LABEL.get(i.severity, i.severity.value), i.rule_id,
            Path(i.path).name, i.line_start, i.title.replace("|", "/")))
    lines += ["", "> 精简版只列清单；完整证据、分析与修复建议见详细版报告。", ""]
    return "\n".join(lines)


def render_print_html(rep, brief: bool = False) -> str:
    esc = html.escape
    rows = []
    for n, i in enumerate(rep.sorted_issues(), 1):
        rows.append(
            "<tr><td>%d</td><td class='s-%s'>%s</td><td>%s</td><td>%s:%d</td>"
            "<td>%s</td></tr>"
            % (n, i.severity.value, _LABEL.get(i.severity, i.severity.value),
               esc(i.rule_id), esc(Path(i.path).name), i.line_start, esc(i.title)))
    detail = ""
    if not brief:
        blocks = []
        for n, i in enumerate(rep.sorted_issues(), 1):
            blocks.append(
                "<div class='item'><h3>%d. [%s] %s</h3>"
                "<p class='meta'>%s · %s:%d · 置信 %.2f</p>"
                "<pre>%s</pre><p>%s</p><p><b>修复：</b>%s</p></div>"
                % (n, _LABEL.get(i.severity, i.severity.value), esc(i.title),
                   esc(i.rule_id), esc(i.path), i.line_start, i.confidence,
                   esc(i.evidence or ""), esc(i.analysis or ""), esc(i.fix or "")))
        detail = "<h2>详细说明</h2>" + "".join(blocks)
    return (
        "<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
        "<title>代码审计报告</title><style>"
        "@page{size:A4;margin:16mm}"
        "body{font-family:'Microsoft YaHei',serif;font-size:11pt;color:#1a1a2e;"
        "line-height:1.6}"
        "h1{font-size:17pt;border-bottom:2px solid #4361ee;padding-bottom:6px}"
        "h2{font-size:13pt;margin-top:18px}h3{font-size:11.5pt;margin:10px 0 4px}"
        "table{border-collapse:collapse;width:100%;font-size:9.5pt}"
        "th,td{border:1px solid #ccd;padding:4px 6px;text-align:left}"
        "th{background:#eef2fa}.item{page-break-inside:avoid;margin-bottom:10px}"
        "pre{background:#f5f7fb;border:1px solid #dde;padding:6px;font-size:9pt;"
        "white-space:pre-wrap;word-break:break-all}"
        ".meta{color:#667;font-size:9pt}.s-critical{color:#c0392b;font-weight:700}"
        ".s-high{color:#d35400}.s-medium{color:#b7950b}.s-low{color:#5d6d7e}"
        "</style></head><body>"
        "<h1>代码审计报告" + ("（精简版）" if brief else "") + "</h1>"
        "<p>审计对象：%s ｜ 引擎：%s ｜ 问题总数：%d</p>"
        % (esc(str(rep.target)), esc(str(rep.engine.get("model", "?"))),
           len(rep.issues))
        + "<h2>问题清单</h2><table><thead><tr><th>#</th><th>级别</th><th>规则</th>"
          "<th>位置</th><th>问题</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>" + detail + "</body></html>")


def to_pdf(rep, out_path, brief: bool = False) -> dict:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        import fitz                                     # PyMuPDF
    except ImportError:
        hp = p.with_suffix(".print.html")
        hp.write_text(render_print_html(rep, brief), encoding="utf-8")
        return {"ok": False, "fallback_html": str(hp),
                "note": "未安装 PyMuPDF，已生成打印版 HTML，浏览器打开后一键另存 PDF"}
    doc = fitz.open()
    W, H = 595, 842                                     # A4 pt
    margin = 46
    state = {"page": doc.new_page(width=W, height=H), "y": 52}
    font = "china-s"

    def newpage():
        state["page"] = doc.new_page(width=W, height=H)
        state["y"] = margin

    def put(text, size=10, gap=4):
        for ln in str(text).split("\n"):
            ln = ln.rstrip()
            if not ln:
                state["y"] += size * 0.6
                continue
            per = max(10, int((W - 2 * margin) / (size * 0.62)))
            for k in range(0, max(1, len(ln)), per):
                seg = ln[k:k + per]
                if state["y"] > H - margin:
                    newpage()
                state["page"].insert_text((margin, state["y"]), seg,
                                          fontsize=size, fontname=font)
                state["y"] += size * 1.45
        state["y"] += gap

    put("代码审计报告" + ("（精简版）" if brief else ""), 16, 8)
    put("审计对象：%s" % rep.target, 10)
    put("引擎：%s ｜ 问题总数：%d" % (rep.engine.get("model", "?"),
                                len(rep.issues)), 10, 10)
    put("问题清单", 13, 6)
    for n, i in enumerate(rep.sorted_issues(), 1):
        put("%d. [%s] %s" % (n, _LABEL.get(i.severity, i.severity.value),
                             i.title), 10.5, 2)
        put("   %s · %s:%d · 置信 %.2f" % (i.rule_id, i.path, i.line_start,
                                         i.confidence), 9, 4)
        if not brief:
            if i.evidence:
                put("   证据：" + i.evidence[:300], 9, 2)
            if i.analysis:
                put("   分析：" + i.analysis[:500], 9, 2)
            if i.fix:
                put("   修复：" + i.fix[:500], 9, 6)
    try:
        doc.save(str(p))
        pages = doc.page_count
    finally:
        doc.close()
    return {"ok": True, "path": str(p), "pages": pages}
