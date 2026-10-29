"""报告生成：Markdown（人读）+ JSON（机读/复跑对比）。

输出结构对应申报书要求：问题分类整理、描述、风险分析、影响范围、
定位信息、修复建议，且每条带知识库来源（可解释、可溯源）。
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import AuditReport, Severity

_ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠",
         Severity.MEDIUM: "🟡", Severity.LOW: "🔵"}
_LABEL = {Severity.CRITICAL: "严重", Severity.HIGH: "高危",
          Severity.MEDIUM: "中危", Severity.LOW: "低危"}
_DET = {"static": "静态规则", "llm": "LLM", "both": "规则+LLM",
        "cross": "双模型共识"}
_CAT = {"security": "安全漏洞", "logic": "逻辑错误",
        "style": "代码规范", "engineering": "工程实践"}


def render_markdown(r: AuditReport) -> str:
    s = r.stats
    lines = [
        "# 代码审计报告", "",
        f"- **审计对象**：`{r.target}`",
        f"- **审计引擎**：{r.engine.get('model', '?')}"
        f"（{'已调用大模型' if r.engine.get('llm_used') else '仅静态规则'}，"
        f"分析单元 {r.engine.get('units', 0)} 个，"
        f"知识库 {r.engine.get('knowledge_loaded', 0)} 条 / 规则 {r.engine.get('rules_loaded', 0)} 条）",
        f"- **结果概览**：共 **{s.get('total', 0)}** 个问题；"
        + "，".join(f"{_LABEL[Severity(k)] if k in [x.value for x in Severity] else k} {v}"
                    for k, v in (s.get("by_severity") or {}).items()) or "无",
        f"- **耗时**：{s.get('elapsed_sec', 0)} 秒", "",
    ]
    if not r.issues:
        lines += ["> ✅ 未发现问题。", ""]
        return "\n".join(lines)

    lines += ["## 问题清单", "",
              "| # | 级别 | 类别 | 规则 | 位置 | 问题 | 检出方式 |",
              "|---|---|---|---|---|---|---|"]
    cr = s.get("cross_review") or {}
    if cr.get("enabled"):
        lines += [f"- **交叉复核**：{cr.get('agreed', 0)} 共识 / "
                  f"{cr.get('single_model', 0)} 单源待确认 / "
                  f"一致率 {cr.get('agreement_rate')}", ""]
    for idx, i in enumerate(r.sorted_issues(), 1):
        loc = f"`{Path(i.path).name}:{i.line_start}`"
        det = _DET.get(i.detector, i.detector)
        lines.append(f"| {idx} | {_ICON[i.severity]}{_LABEL[i.severity]} | {_CAT.get(i.category.value, i.category.value)} "
                     f"| {i.rule_id} | {loc} | {i.title} | {det} |")
    lines.append("")

    lines += ["## 详细说明", ""]
    for idx, i in enumerate(r.sorted_issues(), 1):
        rng = f"{i.line_start}-{i.line_end}" if i.line_end else f"{i.line_start}"
        lines += [
            f"### {idx}. {_ICON[i.severity]}{_LABEL[i.severity]}｜{i.title}", "",
            f"- **位置**：`{i.path}:{rng}`" + (f"（函数 `{i.function_name}`）" if i.function_name else ""),
            f"- **规则**：`{i.rule_id}`" + (f" ｜ 来源：{i.source}" if i.source else ""),
            f"- **检出**：{i.detector} ｜ 置信度 {i.confidence:.2f}"
            + (f" ｜ 命中 {i.votes} 次" if i.votes > 1 else ""),
            "",
            "```python",
            i.evidence or "# （模型未提供证据片段）",
            "```", "",
        ]
        if i.analysis:
            lines += [f"**分析**：{i.analysis}", ""]
        if i.impact:
            lines += [f"**影响**：{i.impact}", ""]
        if i.fix:
            lines += ["**修复建议**：", "", "```python" if "def " in i.fix or "= " in i.fix else "",
                      i.fix, "```" if "def " in i.fix or "= " in i.fix else "", ""]

    if s.get("by_category"):
        lines += ["## 分类统计", ""]
        for k, v in s["by_category"].items():
            lines.append(f"- {_CAT.get(k, k)}：{v}")
        lines.append("")
    return "\n".join(lines)


def render_html(r: AuditReport) -> str:
    """把 Markdown 报告转成带样式的 HTML（D16）。markdown 库缺失时降级为 <pre>。"""
    md = render_markdown(r)
    try:
        import markdown as _md
        body = _md.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        import html as _h
        body = "<pre>" + _h.escape(md) + "</pre>"
    return _HTML_TMPL.replace("{{body}}", body).replace(
        "{{title}}", f"代码审计 · {r.target}")


_HTML_TMPL = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title><style>
body{font-family:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a2e;line-height:1.6}
h1{border-bottom:3px solid #4361ee;padding-bottom:.3rem}
h2{color:#3f37c9;margin-top:2rem;border-left:4px solid #4cc9f0;padding-left:.6rem}
h3{margin-top:1.4rem}
table{border-collapse:collapse;width:100%;font-size:.92rem;margin:1rem 0}
th,td{border:1px solid #d0d7de;padding:.5rem .6rem;text-align:left;vertical-align:top}
th{background:#f6f8fa}tr:nth-child(even){background:#fbfcfe}
code{background:#f0f2f6;padding:.1rem .35rem;border-radius:4px;font-family:Consolas,Menlo,monospace}
pre{background:#0d1117;color:#e6edf3;padding:1rem;border-radius:8px;overflow-x:auto}
pre code{background:none;color:inherit;padding:0}
blockquote{border-left:4px solid #ccc;margin:0;padding:.2rem 1rem;color:#666}
</style></head><body>{{body}}</body></html>"""


_SEV_LABEL = {Severity.CRITICAL: "严重", Severity.HIGH: "高危",
              Severity.MEDIUM: "中危", Severity.LOW: "低危"}


def render_interactive_html(r: AuditReport) -> str:
    """交互式单文件 HTML 报告：严重度/类别/检出方式筛选 + 文件分组折叠 + 关键词搜索。

    数据以 JSON 内嵌、原生 JS 渲染，零外部依赖，浏览器直接打开即可；
    与 render_html（静态打印版）并存，桌面端用本函数。
    """
    items = [{
        "sev": _SEV_LABEL.get(i.severity, i.severity.value),
        "cat": _CAT.get(i.category.value, i.category.value),
        "rule": i.rule_id, "det": _DET.get(i.detector, i.detector),
        "path": i.path, "line": i.line_start, "end": i.line_end or i.line_start,
        "func": i.function_name or "", "title": i.title, "evidence": i.evidence,
        "analysis": i.analysis, "impact": i.impact, "fix": i.fix,
        "source": i.source, "conf": round(i.confidence, 2), "votes": i.votes,
    } for i in r.sorted_issues()]
    meta = {"target": r.target, "engine": r.engine.get("model", "?"),
            "llm": bool(r.engine.get("llm_used")),
            "elapsed": r.stats.get("elapsed_sec", 0), "total": len(items),
            "incr": r.engine.get("incremental")}
    data = json.dumps({"meta": meta, "items": items}, ensure_ascii=False)
    return _IHTML.replace("__DATA__", data.replace("</", "<\\/"))


_IHTML = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>代码审计报告 · 交互版</title><style>
:root{--bg:#f5f8fd;--card:#fff;--line:#dce8f7;--txt:#2b3a52;--dim:#8496b0;--acc:#4a90e2;
--c-critical:#d05c5c;--c-high:#e08a3c;--c-medium:#c9b23d;--c-low:#5a9bd6}
*{box-sizing:border-box;margin:0}body{background:var(--bg);color:var(--txt);font:14px/1.65 "Microsoft YaHei",system-ui,sans-serif;padding:18px 22px}
h1{font-size:17px;margin-bottom:2px}.sub{font-size:12px;color:var(--dim);margin-bottom:12px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.chip{padding:3px 12px;border-radius:14px;font-size:12px;background:var(--card);border:1px solid var(--line);color:var(--dim)}
.chip b{color:var(--txt)}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px;padding:10px 12px;background:var(--card);border:1px solid var(--line);border-radius:8px}
.flabel{font-size:12px;color:var(--dim)}
.opt,.fbtn{padding:3px 12px;border-radius:13px;border:1px solid var(--line);background:#fbfdff;font-size:12px;color:var(--dim);cursor:pointer;user-select:none}
.opt.on,.fbtn.on{border-color:var(--acc);color:var(--acc);background:#eef5fd}
#q{flex:1;min-width:180px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;font-size:13px;background:#fbfdff;color:var(--txt)}
.fbtn{margin-left:auto}
.grp{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:10px;overflow:hidden}
.gh{display:flex;align-items:center;gap:8px;padding:9px 13px;cursor:pointer;font-size:13px;font-weight:600}
.gh:hover{background:#f3f8fe}.gh .arr{transition:transform .15s;font-size:11px;color:var(--dim)}
.grp.closed .arr{transform:rotate(-90deg)}.grp.closed .gb{display:none}
.gh .cnt{margin-left:auto;font-size:11px;color:var(--dim);font-weight:400}
.sevb{font-size:11px;padding:1px 8px;border-radius:9px;color:#fff;flex:none}
.sv0{background:var(--c-critical)}.sv1{background:var(--c-high)}.sv2{background:var(--c-medium)}.sv3{background:var(--c-low)}
.item{border-top:1px solid var(--line);padding:11px 13px}
.ihead{display:flex;align-items:baseline;gap:9px;cursor:pointer;flex-wrap:wrap}
.ihead:hover .ititle{color:var(--acc)}
.ititle{font-size:13.5px;font-weight:600}
.imeta{font-size:11.5px;color:var(--dim)}
.ibody{display:none;margin-top:9px;font-size:13px}
.item.open .ibody{display:block}
.ibody h4{font-size:12px;color:var(--dim);margin:8px 0 3px;font-weight:600}
pre{background:#0d1117;color:#e6edf3;padding:10px 12px;border-radius:6px;font:12px/1.6 Consolas,Menlo,monospace;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
code.loc{font-family:Consolas,monospace;background:#eef2f8;border-radius:4px;padding:0 5px;font-size:12px}
.empty{padding:40px;text-align:center;color:var(--dim)}
</style></head><body>
<h1>代码审计报告</h1><div class="sub" id="sub"></div>
<div class="chips" id="chips"></div>
<div class="filters">
 <span class="flabel">严重度</span><span id="fsev"></span>
 <span class="flabel" style="margin-left:6px">类别</span><span id="fcat"></span>
 <span class="flabel" style="margin-left:6px">检出</span><span id="fdet"></span>
 <input id="q" placeholder="搜索：标题 / 规则 / 文件名 / 代码片段…">
 <button class="fbtn" id="expand">全部展开</button><button class="fbtn" id="collapse">全部折叠</button>
</div>
<div id="list"></div>
<script>
const D = __DATA__;
const SEVS = ["严重","高危","中危","低危"], SVI = {严重:0,高危:1,中危:2,低危:3};
const state = {sev:new Set(),cat:new Set(),det:new Set(),q:""};
const esc = s => String(s==null?"":s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"})[c]);
const fn = p => p.split(/[\\/]/).pop();
const m = D.meta;
document.getElementById("sub").textContent =
  `对象 ${m.target} · 引擎 ${m.engine}${m.llm?"（含大模型）":"（仅静态规则）"} · ${m.elapsed}s`
  + (m.incr ? ` · 增量 ${m.incr.scanned}/${m.incr.changed} 变更文件` : "");
const cs = {}; D.items.forEach(i => cs[i.sev] = (cs[i.sev]||0)+1);
document.getElementById("chips").innerHTML = `<span class="chip">共 <b>${D.items.length}</b> 条</span>`
  + SEVS.filter(s=>cs[s]).map(s=>`<span class="chip" style="color:var(--c-${["critical","high","medium","low"][SVI[s]]})">${s} <b>${cs[s]}</b></span>`).join("");
function mkOpts(el, vals, key){
  el.innerHTML = vals.map(v=>`<span class="opt" data-v="${v}">${v}</span>`).join(" ");
  el.querySelectorAll(".opt").forEach(o=>o.onclick=()=>{
    const v=o.dataset.v; state[key].has(v)?state[key].delete(v):state[key].add(v);
    o.classList.toggle("on"); render(); });
}
mkOpts(document.getElementById("fsev"), SEVS.filter(s=>D.items.some(i=>i.sev===s)), "sev");
mkOpts(document.getElementById("fcat"), [...new Set(D.items.map(i=>i.cat))], "cat");
mkOpts(document.getElementById("fdet"), [...new Set(D.items.map(i=>i.det))], "det");
document.getElementById("q").oninput = e => { state.q = e.target.value.trim().toLowerCase(); render(); };
const pass = i =>
  (!state.sev.size || state.sev.has(i.sev))
  && (!state.cat.size || state.cat.has(i.cat))
  && (!state.det.size || state.det.has(i.det))
  && (!state.q || [i.title,i.rule,i.path,i.evidence,i.analysis,i.fix,i.func].join(" ").toLowerCase().includes(state.q));
const itemHTML = i => `<div class="item"><div class="ihead">
  <span class="sevb sv${SVI[i.sev]}">${i.sev}</span><span class="ititle">${esc(i.title)}</span>
  <span class="imeta"><code class="loc">${esc(fn(i.path))}:${i.line}${i.end!==i.line?"-"+i.end:""}</code>
   · ${esc(i.rule)} · ${esc(i.cat)} · ${esc(i.det)} · 置信 ${i.conf}${i.votes>1?` · ×${i.votes}`:""}</span></div>
 <div class="ibody">${i.func?`<h4>所在函数</h4>${esc(i.func)}`:""}
  <h4>证据代码</h4><pre>${esc(i.evidence)||"（未提供）"}</pre>
  ${i.analysis?`<h4>分析</h4>${esc(i.analysis)}`:""}${i.impact?`<h4>影响</h4>${esc(i.impact)}`:""}
  ${i.fix?`<h4>修复建议</h4><pre>${esc(i.fix)}</pre>`:""}
  ${i.source?`<h4>知识来源</h4>${esc(i.source)}`:""}</div></div>`;
function render(){
  const kept = D.items.filter(pass), byFile = new Map();
  kept.forEach(i => { if(!byFile.has(i.path)) byFile.set(i.path, []); byFile.get(i.path).push(i); });
  const el = document.getElementById("list");
  if(!kept.length){ el.innerHTML = `<div class="empty">无匹配结果（共 ${D.items.length} 条，试试放宽筛选或清空搜索）</div>`; return; }
  el.innerHTML = [...byFile.entries()].sort((a,b)=>b[1].length-a[1].length).map(([p,items])=>{
    const worst = items.reduce((w,i)=>SVI[i.sev]<SVI[w]?i.sev:w, "低危");
    return `<div class="grp"><div class="gh"><span class="arr">▾</span><span class="sevb sv${SVI[worst]}">${worst}</span>
      <b>${esc(fn(p))}</b><span class="imeta">${esc(p)}</span><span class="cnt">${items.length} 条</span></div>
      <div class="gb">${items.map(itemHTML).join("")}</div></div>`; }).join("");
  el.querySelectorAll(".gh").forEach(h=>h.onclick=()=>h.parentElement.classList.toggle("closed"));
  el.querySelectorAll(".ihead").forEach(h=>h.onclick=e=>{ if(!e.target.closest(".ibody")) h.parentElement.classList.toggle("open"); });
}
document.getElementById("expand").onclick=()=>document.querySelectorAll(".grp").forEach(g=>g.classList.remove("closed"));
document.getElementById("collapse").onclick=()=>document.querySelectorAll(".grp").forEach(g=>g.classList.add("closed"));
render();
</script></body></html>"""


def write_report(r: AuditReport, out_md: str | Path,
                 out_json: str | Path | None = None,
                 out_html: str | Path | None = None) -> tuple[Path, Path | None, Path | None]:
    out_md = Path(out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(r), encoding="utf-8")
    jp = None
    if out_json:
        jp = Path(out_json)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(r.to_json(), encoding="utf-8")
    hp = None
    if out_html:
        hp = Path(out_html)
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(render_interactive_html(r), encoding="utf-8")
    return out_md, jp, hp


def load_report_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
