# -*- coding: utf-8 -*-
"""桌面应用 Web 后端（F 项）。

设计：只包壳不改引擎——所有分析走 codeaudit 现有函数。
- GET  /                前端页面
- GET  /api/check       环境自检（密钥/知识库/规则数）
- POST /api/audit       启动审计任务，立即返回 job_id（后台线程跑）
- GET  /api/job/{id}    轮询任务状态与进度日志
- GET  /api/result/{id} 取最终报告（HTML + 统计）

安全：仅监听 127.0.0.1；任务表在内存；不执行被审计代码。
"""
from __future__ import annotations

import contextlib
import io
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from codeaudit import report as RP
from codeaudit import rules as RL
from codeaudit.audit import audit_path
from codeaudit.llm import LLMClient
from codeaudit.retriever import load_knowledge

BASE = Path(__file__).resolve().parent
app = FastAPI(title="LLM Code Audit", docs_url=None, redoc_url=None)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_run_lock = threading.Lock()   # stdout 捕获是进程级的，任务必须串行跑


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
                self._job["progress"].append(line.rstrip())
        return len(s)

    def flush(self) -> None:
        pass


class AuditReq(BaseModel):
    target: str
    depth: str = "file"          # file | function | project
    mode: str = "static"         # static | ai
    examples: bool = True


def _dispatch(req: AuditReq):
    """static：仅规则层（免费秒级）；ai：走完整 audit_path（其进度 print 被捕获）。"""
    if req.mode == "static":
        from codeaudit.models import AuditReport
        target = Path(req.target)
        rs = RL.load_rules()
        rep = AuditReport(target=str(target))
        files = [target] if target.is_file() else sorted(
            p for p in target.rglob("*.py")
            if not any(x in p.parts for x in (".git", "__pycache__", ".venv", "venv")))
        for i, f in enumerate(files, 1):
            src = f.read_text(encoding="utf-8", errors="replace")
            rep.issues.extend(RL.scan_source(src, rs, str(f)))
            print(f"[{i}/{len(files)}] 扫描 {f.name}")
        rep.engine = {"model": "static-rules", "llm_used": False, "depth": req.depth}
        rep.stats = {"total": len(rep.issues),
                     "by_severity": rep.count_by("severity"),
                     "by_category": rep.count_by("category"),
                     "by_detector": rep.count_by("detector"),
                     "elapsed_sec": 0}
        return rep
    return audit_path(req.target, depth=req.depth,
                      use_examples=req.examples or None)


def _run_job(job_id: str, req: AuditReq) -> None:
    job = _jobs[job_id]
    try:
        with _run_lock, contextlib.redirect_stdout(_LineBuf(job)):
            job["progress"].append(
                f"任务开始 · 模式={'AI 深度审计（函数逐个调用模型，慢但深）' if req.mode == 'ai' else '静态规则检查'} · 粒度={req.depth}")
            rep = _dispatch(req)
            job["progress"].append("生成报告中…")
        job["report"] = rep
        job["html"] = RP.render_html(rep)
        job["markdown"] = RP.render_markdown(rep)
        job["status"] = "done"
    except Exception as e:                       # noqa: BLE001 前端需要看到失败原因
        job["error"] = f"{type(e).__name__}: {e}"
        job["status"] = "error"
    finally:
        job["finished_at"] = time.time()


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (BASE / "web" / "index.html").read_text(encoding="utf-8")


@app.get("/api/check")
def check() -> dict:
    client = LLMClient()
    return {
        "llm_ready": client.available(),
        "model": client.model,
        "rules": len(RL.load_rules()),
        "knowledge": len(load_knowledge()),
    }


@app.post("/api/audit")
def start_audit(req: AuditReq) -> dict:
    target = Path(req.target)
    if not target.exists():
        raise HTTPException(404, f"路径不存在：{target}")
    if target.is_file() and target.suffix != ".py":
        raise HTTPException(400, "文件模式仅支持 .py（目录请传文件夹路径）")
    if req.mode == "ai" and not LLMClient().available():
        raise HTTPException(400, "AI 模式需要 .env 配置 LLM_API_KEY；请先用「静态检查」模式")
    job_id = uuid.uuid4().hex[:12]
    with _lock:
        _jobs[job_id] = {"status": "running", "started_at": time.time(),
                         "progress": [], "report": None}
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


@app.get("/api/pick")
def pick(kind: str = "file") -> dict:
    """弹系统文件/目录选择框（后端与前端同机）。kind: file | dir。

    拖拽在 webview 里常拿不到真实路径，改用原生对话框最稳。tkinter 弹在
    主线程外可能受限，异常时返回提示让前端回退到手输路径。
    """
    try:
        import tkinter
        from tkinter import filedialog
        root = tkinter.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if kind == "dir":
            path = filedialog.askdirectory(title="选择要审计的文件夹")
        else:
            path = filedialog.askopenfilename(
                title="选择要审计的 Python 文件",
                filetypes=[("Python 文件", "*.py"), ("所有文件", "*.*")])
        root.destroy()
        return {"path": path or ""}
    except Exception as e:                        # noqa: BLE001
        return {"path": "", "error": f"文件对话框不可用：{type(e).__name__}，请手动输入路径"}


@app.get("/api/result/{job_id}")
def job_result(job_id: str) -> JSONResponse:
    job = _jobs.get(job_id)
    if job is None or job["status"] != "done":
        raise HTTPException(409, "任务未完成")
    rep = job["report"]
    return JSONResponse({"html": job["html"], "markdown": job["markdown"],
                         "stats": rep.stats, "engine": rep.engine})
