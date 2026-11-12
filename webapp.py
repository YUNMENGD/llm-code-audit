# -*- coding: utf-8 -*-
"""桌面应用 Web 后端。

设计：只包壳不改引擎——所有分析走 codeaudit 现有函数。
- GET  /                前端页面
- GET  /api/check       环境自检（密钥/知识库/规则数）
- POST /api/audit       启动审计任务，立即返回 job_id（后台线程跑）
- GET  /api/job/{id}    轮询任务状态与进度日志
- GET  /api/result/{id} 取最终报告（HTML + Markdown + JSON + 统计）
- POST /api/cancel/{id} 取消排队/运行中任务
- GET  /api/history…    审计历史：列表 / 回看 / 删除
- GET/POST /api/settings、POST /api/settings/test   设置中心（密钥脱敏）
- GET/POST/DELETE /api/kb…、POST /api/kb/reindex    知识库管理
- GET/POST/DELETE /api/rules…、POST /api/rules/test 规则库管理
- GET /api/mcp/config、POST /api/mcp/selftest       MCP 接入配置与自检

安全：仅监听 127.0.0.1；任务表在内存且有上限；不执行被审计代码。
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from codeaudit import history as HS
from codeaudit import kbadmin as KA
from codeaudit import mcpconfig as MC
from codeaudit import report as RP
from codeaudit import rules as RL
from codeaudit import settings as ST
from codeaudit.audit import audit_path
from codeaudit.llm import LLMClient
from codeaudit.paths import WEB_DIR
from codeaudit.retriever import load_knowledge

BASE = WEB_DIR
ROOT_OUT = WEB_DIR.parent / "out"          # 导出产物目录（PDF 等，供下载端点取用）
app = FastAPI(title="LLM Code Audit", docs_url=None, redoc_url=None)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_run_lock = threading.Lock()   # stdout 捕获是进程级的，任务必须串行跑
_MAX_JOBS = 30                 # 任务表内存上限：先淘汰最旧的已结束任务
_MAX_PROGRESS = 2000           # 单任务进度日志上限，防长任务撑爆内存


class _LineBuf(io.TextIOBase):
    """把被捕获的 print 按行实时推入 job["progress"]（前端轮询即见进度）。"""

    def __init__(self, job: dict) -> None:
        self._job = job
        self._pending = ""

    def write(self, s: str) -> int:
        self._pending += s
        while "\n" in self._pending:
            line, self._pending = self._pending.split("\n", 1)
            if line.strip():
                prog = self._job["progress"]
                prog.append(line.rstrip())
                if len(prog) > _MAX_PROGRESS:
                    del prog[:len(prog) - _MAX_PROGRESS]
        return len(s)

    def flush(self) -> None:
        pass


class AuditReq(BaseModel):
    target: str
    depth: str = "file"          # file | function | project
    mode: str = "static"         # static | ai
    examples: bool = True
    incremental: bool = False    # 仅审 git 相对 HEAD 的变更 .py（含未跟踪）
    cross_review: bool = False   # 双模型交叉复核（需配置第二模型）
    preset: str = "full"         # full | security | quality
    min_severity: str = "low"    # 只显示 ≥该严重度
    entropy: bool = False        # 高熵密钥检测（可选）
    static_cache: bool = False   # 静态扫描缓存（可选）
    use_ignore: bool = True      # 尊重 .auditignore


class CancelledError(RuntimeError):
    """任务被用户主动取消。"""


def _incremental_only(target: str) -> set[str]:
    """git 变更文件集合；非仓库/无 git 时抛 RuntimeError（job 进度里可见）。"""
    from codeaudit.gitdiff import GitUnavailable, git_changed_files
    p = Path(target)
    try:
        return git_changed_files(p if p.is_dir() else p.parent, base="HEAD")
    except GitUnavailable as e:
        raise RuntimeError(f"增量审计不可用：{e}") from e


def _dispatch(req: AuditReq, job: dict | None = None):
    """static：仅规则层（免费秒级）；ai：走完整 audit_path（其进度 print 被捕获）。"""
    only = None
    if req.incremental:
        only = _incremental_only(req.target)
        print(f"[incremental] git 变更 {len(only)} 个 .py 文件，其余跳过"
              f"（调用图等上下文不受影响）")
        if not only:
            print("[incremental] 相对 HEAD 没有 .py 变更，本次无需扫描")
    if req.mode == "static":
        from codeaudit import entropy as EN
        from codeaudit import jsrules as JR
        from codeaudit import options as OP
        from codeaudit import scancache as SC
        from codeaudit.models import AuditReport
        target = Path(req.target)
        rs = OP.filter_rules(RL.load_rules(), preset=req.preset)
        js_rs = OP.filter_rules(JR.load_js_rules(), preset=req.preset)
        rep = AuditReport(target=str(target))
        files = ([target] if target.is_file()
                 else OP.collect_files(target, {".py"} | JR.JS_EXTS,
                                       use_ignore=req.use_ignore))
        if only is not None:
            files = [p for p in files if str(p.resolve()) in only]
        use_cache = SC.enabled(req.static_cache)
        fp = SC.fingerprint(rs + js_rs)
        skipped, cache_hit = 0, 0
        for i, f in enumerate(files, 1):
            if job is not None and job.get("cancel"):
                raise CancelledError("用户取消")
            try:
                src = f.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                skipped += 1
                print(f"[{i}/{len(files)}] 跳过不可读文件 {f.name}：{e}")
                continue
            rows = SC.get(f, fp) if use_cache else None
            if rows is not None:
                cache_hit += 1
            else:
                found = (JR.scan_js_source(src, js_rs, str(f))
                         if f.suffix in JR.JS_EXTS
                         else RL.scan_source(src, rs, str(f)))
                if req.entropy:
                    found += EN.scan_source(src, str(f))
                rows = [x.to_dict() for x in found]
                if use_cache:
                    SC.put(f, fp, rows)
            rep.issues.extend(SC.rows_to_issues(rows))
            print(f"[{i}/{len(files)}] 扫描 {f.name}")
        if use_cache:
            SC.flush()
            print(f"[cache] 静态缓存命中 {cache_hit}/{len(files)} 个文件")
        rep.engine = {"model": "static-rules", "llm_used": False, "depth": req.depth,
                      "preset": req.preset, "entropy": bool(req.entropy),
                      "static_cache": use_cache}
        if skipped:
            rep.engine["skipped"] = skipped
        if only is not None:
            rep.engine["incremental"] = {"changed": len(only), "scanned": len(files)}
        rep.stats = {"total": len(rep.issues),
                     "by_severity": rep.count_by("severity"),
                     "by_category": rep.count_by("category"),
                     "by_detector": rep.count_by("detector"),
                     "elapsed_sec": 0}
        return OP.filter_report(rep, req.min_severity)
    return audit_path(req.target, depth=req.depth,
                      use_examples=req.examples or None,
                      cross_review=req.cross_review or None,
                      only_files=only, preset=req.preset,
                      min_severity=req.min_severity,
                      entropy=req.entropy or None)


def _run_job(job_id: str, req: AuditReq) -> None:
    job = _jobs[job_id]
    try:
        with _run_lock, contextlib.redirect_stdout(_LineBuf(job)):
            if job.get("cancel"):
                raise CancelledError("用户取消")
            job["progress"].append(
                f"任务开始 · 模式={'AI 深度审计（函数逐个调用模型，慢但深）' if req.mode == 'ai' else '静态规则检查'} · 粒度={req.depth}")
            rep = _dispatch(req, job)
            job["progress"].append("生成报告中…")
        job["report"] = rep
        job["html"] = RP.render_interactive_html(rep)
        job["markdown"] = RP.render_markdown(rep)
        job["json"] = rep.to_json()
        job["status"] = "done"
        try:
            job["hist_id"] = HS.save(rep, {"mode": req.mode, "depth": req.depth})
        except Exception as e:                    # noqa: BLE001 存档失败不影响结果
            job["progress"].append(f"历史存档失败（不影响本次结果）：{e}")
    except CancelledError:
        job["error"] = "任务已取消"
        job["status"] = "cancelled"
    except Exception as e:                       # noqa: BLE001 前端需要看到失败原因
        job["error"] = f"{type(e).__name__}: {e}"
        job["status"] = "error"
    finally:
        job["finished_at"] = time.time()


def _prune_jobs() -> None:
    """任务表超上限时淘汰最旧的已结束任务（调用方需持 _lock）。"""
    if len(_jobs) <= _MAX_JOBS:
        return
    finished = [k for k, v in _jobs.items() if v.get("finished_at")]
    finished.sort(key=lambda k: _jobs[k]["finished_at"])
    for k in finished[:len(_jobs) - _MAX_JOBS]:
        _jobs.pop(k, None)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (BASE / "index.html").read_text(encoding="utf-8")


@app.get("/api/check")
def check() -> dict:
    client = LLMClient()
    reviewer = LLMClient.for_reviewer()
    return {
        "llm_ready": client.available(),
        "model": client.model,
        "rules": len(RL.load_rules()),
        "knowledge": len(load_knowledge()),
        "reviewer_ready": reviewer.available(),
        "reviewer_model": reviewer.model,
        "vector": bool(os.getenv("EMBEDDING_API_KEY", "").strip()
                       or client.available()),
    }


@app.post("/api/audit")
def start_audit(req: AuditReq) -> dict:
    target = Path(req.target)
    if not target.exists():
        raise HTTPException(404, f"路径不存在：{target}")
    from codeaudit.jsrules import JS_EXTS
    if target.is_file() and target.suffix not in ({".py"} | JS_EXTS):
        raise HTTPException(400, "文件模式支持 .py/.js/.ts 等（目录请传文件夹路径）")
    if req.mode == "ai" and not LLMClient().available():
        raise HTTPException(400, "AI 模式需要先在「设置」配置模型密钥；请先用「静态检查」模式")
    job_id = uuid.uuid4().hex[:12]
    with _lock:
        queued = sum(1 for j in _jobs.values() if j["status"] == "running")
        _jobs[job_id] = {"status": "running", "started_at": time.time(),
                         "progress": [], "report": None}
        _prune_jobs()
    if queued:
        _jobs[job_id]["progress"].append(
            f"排队中：前方还有 {queued} 个任务（进度日志按任务串行执行）")
    threading.Thread(target=_run_job, args=(job_id, req), daemon=True).start()
    return {"job_id": job_id}


@app.get("/api/job/{job_id}")
def job_status(job_id: str) -> dict:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "任务不存在")
    return {"status": job["status"],
            "elapsed": round(time.time() - job["started_at"], 1),
            "progress": job["progress"][-60:],
            "error": job.get("error")}


@app.post("/api/cancel/{job_id}")
def cancel_job(job_id: str) -> dict:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "任务不存在")
    if job["status"] != "running":
        return {"ok": False, "status": job["status"]}
    job["cancel"] = True
    return {"ok": True,
            "note": "已请求取消：静态任务在文件间隙停止；AI 任务在当前模型调用返回后停止"}


@app.get("/api/pick")
def pick(kind: str = "file") -> dict:
    """弹系统文件/目录选择框（后端与前端同机）。kind: file | dir。

    拖拽在 webview 里常拿不到真实路径，改用原生对话框最稳。对话框放独立
    线程并设 120s 超时，避免某些环境下 tkinter 挂起拖死请求；异常/超时
    返回提示让前端回退到手输路径。
    """
    holder: dict[str, str] = {}

    def _ask() -> None:
        import tkinter
        from tkinter import filedialog
        root = tkinter.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            if kind == "dir":
                holder["path"] = filedialog.askdirectory(title="选择要审计的文件夹")
            else:
                holder["path"] = filedialog.askopenfilename(
                    title="选择要审计的 Python 文件",
                    filetypes=[("Python 文件", "*.py"), ("所有文件", "*.*")])
        finally:
            root.destroy()

    try:
        t = threading.Thread(target=_ask, daemon=True)
        t.start()
        t.join(timeout=120)
        if t.is_alive():
            return {"path": "", "error": "选择框超时未响应，请手动输入路径"}
        return {"path": holder.get("path") or ""}
    except Exception as e:                        # noqa: BLE001
        return {"path": "", "error": f"文件对话框不可用：{type(e).__name__}，请手动输入路径"}


@app.get("/api/result/{job_id}")
def job_result(job_id: str) -> JSONResponse:
    job = _jobs.get(job_id)
    if job is None or job["status"] != "done":
        raise HTTPException(409, "任务未完成")
    rep = job["report"]
    return JSONResponse({"html": job["html"], "markdown": job["markdown"],
                         "json": job.get("json", rep.to_json()),
                         "stats": rep.stats, "engine": rep.engine,
                         "hist_id": job.get("hist_id", "")})


class FeedbackReq(BaseModel):
    rule: str
    title: str
    path: str = ""
    line: int | None = None
    detector: str = ""
    evidence: str = ""


@app.post("/api/feedback")
def add_feedback(req: FeedbackReq) -> dict:
    """误报标记入队（G）：data/feedback/queue.json，键去重累计计数。"""
    from codeaudit import feedback as FB
    try:
        rec = FB.add(req.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "count": rec["count"], "key": rec["key"]}


@app.get("/api/feedback")
def feedback_stats() -> dict:
    from codeaudit import feedback as FB
    return FB.stats()


# ---------- 审计历史 ----------

@app.get("/api/history")
def history_list(limit: int = 50) -> dict:
    return {"items": HS.list_history(limit)}


@app.get("/api/history-trend")
def history_trend(target: str = "", limit: int = 200) -> dict:
    from codeaudit import trend as TD
    agg = TD.aggregate(limit=limit, target=target or None)
    agg["svg"] = TD.render_trend_svg(agg)
    return agg


@app.get("/api/history/{hist_id}")
def history_report(hist_id: str) -> JSONResponse:
    try:
        rep = HS.load_report(hist_id)
    except FileNotFoundError:
        raise HTTPException(404, "历史记录不存在")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return JSONResponse({"html": RP.render_interactive_html(rep),
                         "markdown": RP.render_markdown(rep),
                         "json": rep.to_json(),
                         "stats": rep.stats, "engine": rep.engine})


@app.delete("/api/history/{hist_id}")
def history_delete(hist_id: str) -> dict:
    try:
        HS.delete(hist_id)
    except FileNotFoundError:
        raise HTTPException(404, "历史记录不存在")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


# ---------- 设置中心 ----------

@app.get("/api/settings")
def settings_get() -> dict:
    return {"fields": ST.snapshot()}


@app.post("/api/settings")
def settings_save(payload: dict) -> dict:
    updates = payload.get("updates") if isinstance(payload, dict) else None
    if not isinstance(updates, dict):
        raise HTTPException(400, "请求体需为 {updates: {键: 值}}")
    try:
        changed = ST.save(updates)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "changed": changed}


@app.post("/api/settings/test")
def settings_test() -> dict:
    return ST.test_connection()


# ---------- 知识库管理 ----------

@app.get("/api/kb")
def kb_list() -> dict:
    return {"items": KA.list_items()}


class KBItemReq(BaseModel):
    id: str
    title: str
    category: str = "security"
    severity: str = "medium"
    pattern: str = ""
    impact: str = ""
    fix: str = ""
    source: str = ""
    tags: list[str] = []
    triggers: list[str] = []


@app.post("/api/kb")
def kb_save(req: KBItemReq) -> dict:
    try:
        item, created = KA.save_item(req.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "created": created, "id": item["id"]}


@app.delete("/api/kb/{item_id}")
def kb_delete(item_id: str) -> dict:
    try:
        KA.delete_item(item_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/api/kb/reindex")
def kb_reindex() -> dict:
    return KA.reindex()


# ---------- 规则库管理 ----------

@app.get("/api/rules")
def rules_list() -> dict:
    return {"rules": KA.list_rules()}


class RuleReq(BaseModel):
    id: str
    title: str
    pattern: str
    category: str = "security"
    severity: str = "medium"
    source: str = ""
    why: str = ""
    impact: str = ""
    suggestion: str = ""
    exclude: list[str] = []


@app.post("/api/rules")
def rules_save(req: RuleReq) -> dict:
    try:
        rule, created = KA.save_rule(req.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "created": created, "id": rule["id"]}


@app.delete("/api/rules/{rule_id}")
def rules_delete(rule_id: str) -> dict:
    try:
        KA.delete_rule(rule_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


class RuleTestReq(BaseModel):
    pattern: str
    sample: str = ""


@app.post("/api/rules/test")
def rules_test(req: RuleTestReq) -> dict:
    try:
        return {"ok": True, "hits": KA.test_pattern(req.pattern, req.sample)}
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------- 脱敏分享 ----------

class ShareReq(BaseModel):
    hist_id: str = ""
    job_id: str = ""
    watermark: str = ""


@app.post("/api/share")
def share_report(req: ShareReq) -> dict:
    """生成脱敏分享版 HTML：优先历史 ID，其次当前任务 ID。"""
    rep = None
    if req.hist_id:
        try:
            rep = HS.load_report(req.hist_id)
        except FileNotFoundError:
            raise HTTPException(404, "历史记录不存在")
        except ValueError as e:
            raise HTTPException(400, str(e))
    elif req.job_id:
        job = _jobs.get(req.job_id)
        if job is None or job["status"] != "done":
            raise HTTPException(409, "任务不存在或未完成")
        rep = job["report"]
    else:
        raise HTTPException(400, "需提供 hist_id 或 job_id")
    return {"html": RP.render_share_html(rep, req.watermark)}


# ---------- 审计对比 / 一键修复 ----------

@app.get("/api/history-diff")
def history_diff(old: str, new: str, drift: int = 3) -> dict:
    from codeaudit.diff import diff_reports, render_diff_markdown
    try:
        a, b = HS.load_report(old), HS.load_report(new)
    except FileNotFoundError:
        raise HTTPException(404, "历史记录不存在")
    except ValueError as e:
        raise HTTPException(400, str(e))
    d = diff_reports(a, b, drift=drift)
    d["markdown"] = render_diff_markdown(d, old_label=old, new_label=new)
    return d


class FixReq(BaseModel):
    path: str
    issue: dict


@app.post("/api/fix/preview")
def fix_preview(req: FixReq) -> dict:
    from codeaudit import fixer
    return fixer.preview(req.path, req.issue)


@app.post("/api/fix/apply")
def fix_apply(req: FixReq) -> dict:
    from codeaudit import fixer
    r = fixer.apply(req.path, req.issue)
    if not r.get("ok"):
        raise HTTPException(400, r.get("error", "修复失败"))
    return r


# ---------- MCP 接入 ----------

@app.get("/api/mcp/config")
def mcp_config() -> dict:
    return MC.client_config()


@app.post("/api/mcp/selftest")
def mcp_selftest() -> dict:
    return MC.selftest()


# ---------- 可选功能：选项 / 规则开关 / 忽略清单 ----------

@app.get("/api/options")
def options_get(root: str = "") -> dict:
    from codeaudit import options as OP
    o = OP.load_options()
    rules = [{"id": r["id"], "title": r.get("title", ""),
              "category": r.get("category", ""), "severity": r.get("severity", ""),
              "builtin": r.get("_builtin", True),
              "enabled": r["id"] not in o["disabled_rules"]}
             for r in KA.list_rules()]
    return {"options": o, "presets": OP.PRESETS, "rules": rules,
            "severities": OP.SEV_ORDER,
            "ignore_text": OP.read_ignore_text(root) if root else "",
            "ignore_name": OP.IGNORE_NAME}


@app.post("/api/options")
def options_save(payload: dict) -> dict:
    from codeaudit import options as OP
    try:
        o = OP.save_options(payload.get("updates") or {})
        if payload.get("ignore_text") is not None and payload.get("root"):
            OP.write_ignore_text(payload["root"], payload["ignore_text"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    except OSError as e:
        raise HTTPException(400, f"忽略清单写入失败：{e}")
    return {"ok": True, "options": o}


@app.post("/api/options/rule")
def options_rule(payload: dict) -> dict:
    from codeaudit import options as OP
    rid = str(payload.get("id", ""))
    if not rid:
        raise HTTPException(400, "缺少规则 ID")
    return {"ok": True, "options": OP.set_rule_switch(rid, bool(payload.get("enabled")))}


@app.post("/api/options/clear-cache")
def options_clear_cache() -> dict:
    from codeaudit import scancache as SC
    return SC.clear()


# ---------- SARIF / PDF / 精简版导出 ----------

class ExportReq(BaseModel):
    hist_id: str = ""
    job_id: str = ""
    brief: bool = False


def _rep_from_ref(hist_id: str, job_id: str):
    if hist_id:
        try:
            return HS.load_report(hist_id)
        except FileNotFoundError:
            raise HTTPException(404, "历史记录不存在")
        except ValueError as e:
            raise HTTPException(400, str(e))
    job = _jobs.get(job_id)
    if job is None or job["status"] != "done":
        raise HTTPException(409, "任务不存在或未完成")
    return job["report"]


@app.post("/api/export/sarif")
def export_sarif(req: ExportReq) -> dict:
    from codeaudit import sarif as SF
    rep = _rep_from_ref(req.hist_id, req.job_id)
    return {"sarif": SF.to_sarif(rep, root=Path(rep.target))}


@app.post("/api/export/brief")
def export_brief(req: ExportReq) -> dict:
    from codeaudit import pdfout as PD
    rep = _rep_from_ref(req.hist_id, req.job_id)
    return {"markdown": PD.render_brief_markdown(rep),
            "html": PD.render_print_html(rep, brief=True)}


@app.post("/api/export/pdf")
def export_pdf(req: ExportReq) -> dict:
    from codeaudit import pdfout as PD
    rep = _rep_from_ref(req.hist_id, req.job_id)
    out = ROOT_OUT / f"审计报告-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    r = PD.to_pdf(rep, out, brief=req.brief)
    if r.get("ok"):
        r["download_url"] = "/api/download?name=" + out.name
    return r


@app.get("/api/download")
def download_file(name: str):
    from fastapi.responses import FileResponse
    safe = Path(name).name
    p = ROOT_OUT / safe
    if not p.exists() or p.parent != ROOT_OUT:
        raise HTTPException(404, "文件不存在")
    return FileResponse(str(p), filename=safe)


# ---------- 误报评审 + 人工标注 ----------

@app.get("/api/review")
def review_list() -> dict:
    from codeaudit import review as RV
    return {"items": RV.rows(), "stats": RV.stats()}


@app.post("/api/review/decision")
def review_decision(payload: dict) -> dict:
    from codeaudit import review as RV
    try:
        return RV.set_decision(str(payload.get("key", "")),
                               str(payload.get("decision", "")),
                               str(payload.get("note", "")))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/review/apply")
def review_apply(payload: dict) -> dict:
    from codeaudit import review as RV
    return RV.apply_adopted(dry_run=not bool(payload.get("write")))


@app.post("/api/annotate/items")
def annotate_items(req: ExportReq) -> dict:
    from codeaudit import review as RV
    rep = _rep_from_ref(req.hist_id, req.job_id)
    return {"items": RV.annotate_items(rep)}


@app.post("/api/annotate/save")
def annotate_save(payload: dict) -> dict:
    from codeaudit import review as RV
    try:
        return RV.save_annotations(str(payload.get("name", "annot")),
                                   payload.get("items") or [],
                                   payload.get("verdicts") or {})
    except (ValueError, OSError) as e:
        raise HTTPException(400, str(e))


@app.get("/api/annotate/list")
def annotate_list() -> dict:
    from codeaudit import review as RV
    return {"items": RV.list_annotations()}


# ---------- 规则/知识包 ----------

@app.get("/api/pack/export")
def pack_export() -> dict:
    from codeaudit import packs as PK
    return {"pack": PK.export_pack()}


@app.post("/api/pack/import")
def pack_import(payload: dict) -> dict:
    from codeaudit import packs as PK
    try:
        return PK.import_pack(payload.get("pack") or {},
                              dry_run=bool(payload.get("dry_run")))
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------- 依赖扫描 / 钩子 / 通知 ----------

@app.post("/api/depscan")
def depscan_run(payload: dict) -> dict:
    from codeaudit import depscan as DS
    target = str(payload.get("target", "")).strip()
    if not target or not Path(target).exists():
        raise HTTPException(400, "目标路径不存在")
    r = DS.scan(target)
    return {"ok": r["ok"], "tools": r["tools"], "note": r["note"],
            "manifests": r.get("manifests", []),
            "issues": [i.to_dict() for i in r["issues"]]}


@app.post("/api/hook")
def hook_manage(payload: dict) -> dict:
    from codeaudit import hooks as HK
    repo = str(payload.get("repo", "")).strip()
    if not repo or not Path(repo).exists():
        raise HTTPException(400, "仓库路径不存在")
    action = payload.get("action", "render")
    thr = str(payload.get("threshold", "high"))
    if action == "install":
        r = HK.install(repo, threshold=thr, python=sys.executable,
                       force=bool(payload.get("force")))
    elif action == "uninstall":
        r = HK.uninstall(repo)
    else:
        r = {"ok": True, "script": HK.render(thr, sys.executable)}
    if not r.get("ok"):
        raise HTTPException(400, r.get("note", "操作失败"))
    return r


@app.post("/api/notify/test")
def notify_test() -> dict:
    from codeaudit import notify as NT
    from codeaudit import options as OP
    o = OP.load_options()
    return NT.notify_done({"target_name": "连通性测试", "total": 0,
                           "by_severity": {}, "mode": "test",
                           "elapsed_sec": 0},
                          {"notify": True, "webhook": o.get("webhook", "")})
