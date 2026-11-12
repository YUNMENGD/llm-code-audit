"""命令行入口。

用法：
  python -m codeaudit check <路径>                     仅静态规则（免密钥）
  python -m codeaudit audit <路径> [-d depth] [-o out/report.md] [--html x.html]
  python -m codeaudit rules                            列出规则库
  python -m codeaudit kb <关键词> [-n 5]               检索知识库
  python -m codeaudit selfcheck                        自检环境
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import parser as P
from . import retriever as R
from . import rules as RL
from .llm import LLMClient


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="codeaudit",
                                 description="基于大语言模型的代码审计系统")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("check", "audit"):
        s = sub.add_parser(name, help="静态检查" if name == "check" else "完整审计")
        s.add_argument("target", help="要审计的文件或目录")
        s.add_argument("--preset", choices=["full", "security", "quality"],
                       default=None, help="审计预设：安全专项 / 代码质量 / 全量（默认）")
        s.add_argument("--min-severity", dest="min_severity", default=None,
                       choices=["critical", "high", "medium", "low"],
                       help="只显示/统计 ≥该严重度的问题")
        s.add_argument("--entropy", action="store_true", default=False,
                       help="启用高熵密钥检测（可选启发式，置信度 0.6）")
        s.add_argument("--no-ignore", dest="no_ignore", action="store_true",
                       default=False, help="忽略 .auditignore，扫描全部文件")
        s.add_argument("--sarif", dest="sarif", default=None, metavar="PATH",
                       help="同时导出 SARIF 2.1.0（GitHub Code Scanning 可直接读）")
        s.add_argument("--changed-since", dest="changed", metavar="REV",
                       default=None,
                       help="增量审计：只审 git 中相对 REV（如 HEAD~3，默认 HEAD=工作区变更）"
                            "新增/修改的 .py/.js/.ts 文件；调用图等上下文仍按全库构建")
        if name == "check":
            s.add_argument("--static-cache", dest="static_cache", action="store_true",
                           default=False, help="启用静态扫描缓存（内容哈希+规则指纹）")
            s.add_argument("--workers", type=int, default=None, metavar="N",
                           help="并行扫描进程数（默认自动：<64 文件串行，"
                                "≥64 用 CPU-1；1=强制串行）")
        if name == "audit":
            s.add_argument("-d", "--depth", choices=["function", "file", "project"],
                           default="file", help="审计粒度")
            s.add_argument("-o", "--out", default="out/report.md")
            s.add_argument("-j", "--json", dest="json_out", default="out/report.json")
            s.add_argument("--no-examples", dest="examples", action="store_false",
                           default=None,
                           help="关闭 few-shot 校准示例（A/B 对比用；也可用环境变量 PROMPT_EXAMPLES=0）")
            s.add_argument("--html", dest="html_out", default=None, metavar="PATH",
                           help="同时输出 HTML 报告（如 out/report.html）")
            s.add_argument("--brief", action="store_true", default=False,
                           help="精简版报告（只给清单+统计）")
            s.add_argument("--pdf", dest="pdf_out", default=None, metavar="PATH",
                           help="导出 PDF（无 PyMuPDF 时降级为打印版 HTML）")
            s.add_argument("--share", dest="share_out", default=None, metavar="PATH",
                           help="同时输出脱敏分享版 HTML（路径只留文件名、凭据掩码）")
            s.add_argument("--watermark", default="", metavar="TEXT",
                           help="分享版水印文字（默认「脱敏分享版」）")
            s.add_argument("--cross-review", dest="cross", action="store_true",
                           default=None,
                           help="启用 D15 双模型交叉复核（需配置 LLM2_API_KEY；两模型并发调用）")
            s.add_argument("--no-cache", dest="cache", action="store_false",
                           default=None,
                           help="关闭 D17 增量缓存（默认开启：同一代码重审不再调模型）")
            s.add_argument("--fail-on", dest="fail_on", default="none",
                           choices=["none", "low", "medium", "high", "critical"],
                           metavar="SEV",
                           help="CI 门禁：存在 ≥该严重度的问题时退出码 1（默认 none 不启用）")

    sub.add_parser("rules", help="列出规则库")
    k = sub.add_parser("kb", help="检索知识库")
    k.add_argument("query")
    k.add_argument("-n", type=int, default=5)
    ev = sub.add_parser("eval", help="评测基准：precision/recall/F1")
    ev.add_argument("bench", nargs="?", default="examples/bench")
    ev.add_argument("--static", action="store_true",
                    help="仅静态规则（免密钥验证评测器）")
    ev.add_argument("--runs", type=int, default=1,
                    help="多轮评测（配合 D17 缓存，追加轮近似免费）")
    ev.add_argument("--cross-review", dest="cross", action="store_true", default=None)
    rev = sub.add_parser("real-eval",
                         help="真实开源库基准：只测 precision（需 realtest/ 已下载）")
    rev.add_argument("libs", nargs="*", default=[],
                     help="库名（realtest/ 下目录名，如 click）；留空则评测 bench-real/ 全部")
    sub.add_parser("selfcheck", help="环境自检")
    sub.add_parser("mcp", help="启动 MCP 服务器（stdio），供 Claude Desktop/Cursor 等客户端接入")
    df = sub.add_parser("diff", help="对比两份审计报告（JSON），输出新增/消除/移动")
    df.add_argument("old", help="旧报告 JSON 路径")
    df.add_argument("new", help="新报告 JSON 路径")
    df.add_argument("--drift", type=int, default=3, help="行号漂移容忍（默认3）")
    df.add_argument("-o", "--out", default=None, help="对比结果 Markdown 输出路径")
    tr = sub.add_parser("trend", help="审计历史趋势：问题数/严重度随时间变化")
    tr.add_argument("--target", default=None, help="只统计该目标（按路径尾段匹配）")
    tr.add_argument("--svg", default=None, metavar="PATH", help="导出趋势 SVG 图")
    hk = sub.add_parser("hook", help="生成/安装 Git pre-commit 钩子（提交前增量门禁）")
    hk.add_argument("--install", action="store_true", help="写入本仓库 .git/hooks/pre-commit")
    hk.add_argument("--uninstall", action="store_true", help="卸载本工具生成的钩子")
    hk.add_argument("--force", action="store_true", help="覆盖已存在的钩子")
    hk.add_argument("--threshold", default="high",
                    choices=["critical", "high", "medium", "low"])
    hk.add_argument("--out", default=None, metavar="PATH", help="把钩子脚本写到指定文件")
    pk = sub.add_parser("pack", help="规则/知识包导入导出（团队共享自定义弹药）")
    pk.add_argument("action", choices=["export", "import"])
    pk.add_argument("file", help="包文件路径")
    pk.add_argument("--dry-run", dest="dry", action="store_true", help="只校验不写入")
    rw = sub.add_parser("review", help="误报反馈评审（采纳/驳回/过闸门写入）")
    rw.add_argument("action", choices=["list", "adopt", "reject", "apply"], nargs="?",
                    default="list")
    rw.add_argument("--key", default=None, help="反馈键（adopt/reject 用）")
    rw.add_argument("--note", default="")
    rw.add_argument("--write", action="store_true", help="apply 时真正写入知识库")
    dp = sub.add_parser("depscan", help="依赖漏洞扫描（需本机 pip-audit / npm）")
    dp.add_argument("target", nargs="?", default=".")
    ex = sub.add_parser("export", help="把已有报告 JSON 转成 SARIF / PDF / 精简版")
    ex.add_argument("report", help="审计报告 JSON 路径")
    ex.add_argument("--sarif", default=None, metavar="PATH")
    ex.add_argument("--pdf", default=None, metavar="PATH")
    ex.add_argument("--brief", action="store_true")

    a = ap.parse_args(argv)

    if a.cmd == "hook":
        from . import hooks as HK
        if a.install:
            r = HK.install(Path.cwd(), threshold=a.threshold,
                           python=sys.executable, force=a.force)
        elif a.uninstall:
            r = HK.uninstall(Path.cwd())
        elif a.out:
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(HK.render(a.threshold, sys.executable),
                                   encoding="utf-8", newline="\n")
            r = {"ok": True, "path": a.out}
        else:
            print(HK.render(a.threshold, sys.executable))
            return 0
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r.get("ok") else 1
    if a.cmd == "pack":
        from . import packs as PK
        if a.action == "export":
            print(json.dumps(PK.write_pack(a.file), ensure_ascii=False))
            return 0
        pack = json.loads(Path(a.file).read_text(encoding="utf-8"))
        r = PK.import_pack(pack, dry_run=a.dry)
        print("导入 %d 条，跳过 %d 条" % (r["added_count"], r["skipped_count"]))
        for s in r["skipped"][:10]:
            print("  跳过 %s：%s" % (s["id"], s["reason"]))
        return 0
    if a.cmd == "review":
        from . import review as RV
        if a.action == "list":
            for r in RV.rows():
                print("[%s] %s ×%s  %s" % (r["decision"], r.get("rule"),
                                           r.get("count"), r.get("key")))
            print(json.dumps(RV.stats(), ensure_ascii=False))
            return 0
        if a.action in ("adopt", "reject"):
            print(json.dumps(RV.set_decision(a.key or "", a.action, a.note),
                             ensure_ascii=False))
            return 0
        r = RV.apply_adopted(dry_run=not a.write)
        print(json.dumps({k: v for k, v in r.items() if k != "proposals"},
                         ensure_ascii=False))
        return 0 if r.get("ok") else 1
    if a.cmd == "depscan":
        from . import depscan as DS
        r = DS.scan(a.target)
        print("工具：%s ｜ 漏洞 %d 条 %s" % (r["tools"], len(r["issues"]), r["note"]))
        for i in r["issues"][:30]:
            print("  [%s] %s" % (i.severity.value, i.title))
        return 0
    if a.cmd == "export":
        from . import pdfout as PD, sarif as SF
        from .models import AuditReport
        from .scancache import rows_to_issues
        raw = json.loads(Path(a.report).read_text(encoding="utf-8"))
        rep = AuditReport(target=raw.get("target", ""),
                          engine=raw.get("engine", {}), stats=raw.get("stats", {}))
        rep.issues = rows_to_issues(raw.get("issues", []))
        if a.sarif:
            print(json.dumps(SF.write_sarif(rep, a.sarif), ensure_ascii=False))
        if a.pdf:
            print(json.dumps(PD.to_pdf(rep, a.pdf, brief=a.brief), ensure_ascii=False))
        if a.brief and not a.pdf:
            print(PD.render_brief_markdown(rep))
        return 0

    if a.cmd == "trend":
        from . import trend as TD
        agg = TD.aggregate(target=a.target)
        s = agg["summary"]
        print(f"审计 {s['runs']} 次 · 问题数 {s['first_total']} → {s['last_total']}"
              f"（{'+' if s['delta'] >= 0 else ''}{s['delta']}）· 峰值 {s['max_total']}")
        for p in agg["points"]:
            print(f"  {p['time_str']}  总{p['total']:>3}  "
                  f"严{p['critical']} 高{p['high']} 中{p['medium']} 低{p['low']}  "
                  f"{Path(p['target']).name}")
        if a.svg:
            Path(a.svg).parent.mkdir(parents=True, exist_ok=True)
            Path(a.svg).write_text(TD.render_trend_svg(agg), encoding="utf-8")
            print(f"趋势图 → {a.svg}")
        return 0
    if a.cmd == "mcp":
        from .mcpserver import serve
        return serve()
    if a.cmd == "diff":
        from .diff import diff_reports, render_diff_markdown
        d = diff_reports(a.old, a.new, drift=a.drift)
        md = render_diff_markdown(d, old_label=Path(a.old).name,
                                  new_label=Path(a.new).name)
        print(md)
        if a.out:
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(md, encoding="utf-8")
        return 1 if d["summary"]["added"] else 0
    if a.cmd == "selfcheck":
        return _selfcheck()
    if a.cmd == "rules":
        rs = RL.load_rules()
        print(f"规则库共 {len(rs)} 条：")
        for r in rs:
            print(f"  {r['id']:<14} [{r['severity']:<8}] {r['title']}")
        return 0
    if a.cmd == "kb":
        items = R.retrieve(a.query, top_k=a.n)
        print(f"知识库命中 {len(items)} 条：")
        for it in items:
            print(f"  [{it['id']}] {it['title']}（score={it['score']}，{it.get('source', '')}）")
        return 0

    if a.cmd == "eval":
        from .evalb import run_eval
        res = run_eval(a.bench, static_only=a.static, runs=a.runs,
                       cross_review=a.cross)
        mode = "静态规则" if a.static else "完整审计"
        for n, p in enumerate(res["runs"], 1):
            print(f"[{mode} 第{n}轮] TP={p['tp']} FP={len(p['fp'])} FN={len(p['fn'])} "
                  f"建议={p['advisory']} "
                  f"P={p['precision']:.3f} R={p['recall']:.3f} F1={p['f1']:.3f}")
            for x in p["fp"]:
                print(f"    误报: {x}")
            for x in p["fn"]:
                print(f"    漏报: {x}")
        avg = res["avg"]
        print(f"均值: P={avg['precision']:.3f} R={avg['recall']:.3f} "
              f"F1={avg['f1']:.3f} | 多轮稳定={res['stable_across_runs']}")
        return 0 if avg["precision"] >= 0.8 and avg["recall"] >= 0.8 else 1

    if a.cmd == "real-eval":
        from .realeval import main as real_main
        return real_main(a.libs)

    # 增量审计文件集合（--changed-since）：git 不可用/非仓库时直接报错退出
    only = None
    if getattr(a, "changed", None) is not None:
        from .gitdiff import GitUnavailable, git_changed_files
        try:
            only = git_changed_files(a.target if Path(a.target).is_dir()
                                     else Path(a.target).parent,
                                     base=a.changed or "HEAD")
        except GitUnavailable as e:
            print(f"增量审计不可用：{e}")
            return 2
        if not only:
            print(f"增量审计：相对 {a.changed or 'HEAD'} 无 .py 变更，无需扫描")
            return 0

    if a.cmd == "check":
        from .report import render_markdown
        from .models import AuditReport
        from . import jsrules as JR
        from . import options as OP
        from . import scancache as SC
        from . import entropy as EN
        from . import parallel as PL
        tp = Path(a.target)
        files = ([tp] if tp.is_file() else OP.collect_files(
            tp, {".py"} | JR.JS_EXTS, use_ignore=not a.no_ignore))
        if only is not None:
            files = [p for p in files if str(p.resolve()) in only]
            print(f"增量模式：{len(files)} 个变更文件（上下文外文件已跳过）")
        all_rules = OP.filter_rules(RL.load_rules(), preset=a.preset)
        js_rules = OP.filter_rules(JR.load_js_rules(), preset=a.preset)
        use_cache = SC.enabled(a.static_cache)
        fp = SC.fingerprint(all_rules + js_rules)
        issues, cache_hit = [], 0
        workers = getattr(a, "workers", None)
        if not use_cache and not a.entropy and workers != 1 \
                and PL.default_workers(len(files)) > 1:
            issues, skipped = PL.scan_files_parallel(files, workers=workers)
            if skipped:
                print(f"跳过不可读文件 {skipped} 个")
        else:
            for f in files:
                try:
                    src = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rows = SC.get(f, fp) if use_cache else None
                if rows is not None:
                    cache_hit += 1
                else:
                    found = (JR.scan_js_source(src, js_rules, str(f))
                             if f.suffix in JR.JS_EXTS
                             else RL.scan_source(src, all_rules, str(f)))
                    if a.entropy:
                        found += EN.scan_source(src, str(f))
                    rows = [i.to_dict() for i in found]
                    if use_cache:
                        SC.put(f, fp, rows)
                issues += SC.rows_to_issues(rows)
        if use_cache:
            SC.flush()
            print(f"静态缓存：命中 {cache_hit}/{len(files)} 个文件")
        rep = AuditReport(target=a.target, issues=issues,
                          engine={"model": "static-only", "llm_used": False,
                                  "units": len(files), "rules_loaded": len(all_rules),
                                  "knowledge_loaded": len(R.load_knowledge()),
                                  "preset": a.preset or OP.load_options()["preset"],
                                  "entropy": bool(a.entropy)},
                          stats={"total": len(issues),
                                 "by_severity": {}, "by_category": {}, "by_detector": {}})
        rep.stats["by_severity"] = rep.count_by("severity")
        rep.stats["by_category"] = rep.count_by("category")
        rep = OP.filter_report(rep, a.min_severity)
        print(render_markdown(rep))
        if a.sarif:
            from . import sarif as SF
            r = SF.write_sarif(rep, a.sarif, root=tp if tp.is_dir() else tp.parent)
            print(f"SARIF → {r['path']}（{r['results']} 条）")
        return 1 if any(i.severity.value in ("critical", "high")
                        for i in rep.issues) else 0

    # audit
    from .audit import audit_path
    from .report import write_report
    print(f"审计 {a.target}（粒度 {a.depth}）...")
    rep = audit_path(a.target, depth=a.depth, use_examples=a.examples,
                     cross_review=a.cross, use_cache=a.cache,
                     only_files=only, preset=a.preset,
                     min_severity=a.min_severity, entropy=a.entropy or None)
    if a.brief:
        from . import pdfout as PD
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(PD.render_brief_markdown(rep), encoding="utf-8")
    md, js, hp = write_report(rep, a.out, a.json_out, a.html_out)
    if a.sarif:
        from . import sarif as SF
        r = SF.write_sarif(rep, a.sarif, root=Path(a.target))
        print(f"SARIF → {r['path']}（{r['results']} 条）")
    if a.pdf_out:
        from . import pdfout as PD
        print("PDF → " + json.dumps(PD.to_pdf(rep, a.pdf_out, brief=a.brief),
                                    ensure_ascii=False))
    from . import notify as NT
    from . import options as OP
    _opts = OP.load_options()
    if _opts.get("notify") or _opts.get("webhook"):
        NT.notify_done({"target_name": Path(a.target).name,
                        "total": rep.stats.get("total", 0),
                        "by_severity": rep.stats.get("by_severity", {}),
                        "mode": "ai" if rep.engine.get("llm_used") else "static",
                        "elapsed_sec": rep.stats.get("elapsed_sec", 0)}, _opts)
    extra = f"、{hp}" if hp else ""
    if a.share_out:
        from .report import render_share_html
        sp = Path(a.share_out)
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(render_share_html(rep, a.watermark), encoding="utf-8")
        extra += f"、分享版 {sp}"
    print(f"完成：{rep.stats['total']} 个问题 → {md}{extra}")
    cr = rep.stats.get("cross_review") or {}
    if cr.get("enabled"):
        print(f"交叉复核：共识 {cr['agreed']} / 单源待确认 {cr['single_model']}"
              f" / 一致率 {cr['agreement_rate']}")
    cs = rep.stats.get("cache")
    if cs:
        print(f"缓存：命中 {cs['hit']} / 未命中 {cs['miss']}"
              f"（未命中=本次实际计费调用数）")
    if not rep.engine["llm_used"]:
        print("提示：未检测到大模型 API Key，本次仅静态规则结果。配置 .env 后可获得语义级审计。")
    if a.fail_on != "none":
        from .models import Severity
        order = [s.value for s in Severity]          # critical→low，声明序即严重度序
        thr = order.index(a.fail_on)
        bad = [i for i in rep.issues if order.index(i.severity.value) <= thr]
        if bad:
            print(f"[gate] {len(bad)} 个问题达到 ≥{a.fail_on}，按门禁失败退出")
            for i in bad[:10]:
                print(f"  · {i.severity.value:8s} {i.rule_id} {i.path}:{i.line_start} {i.title}")
            return 1
        print(f"[gate] 无 ≥{a.fail_on} 问题，门禁通过")
    return 0


def _selfcheck() -> int:
    c = LLMClient()
    print(f"python: {sys.version.split()[0]}")
    print(f"规则库: {len(RL.load_rules())} 条")
    print(f"知识库: {len(R.load_knowledge())} 条")
    print(f"Prompt: 函数级 {'有' if (Path(__file__).parent.parent / 'prompts' / 'function_audit.md').exists() else '缺'} / "
          f"文件级 {'有' if (Path(__file__).parent.parent / 'prompts' / 'file_audit.md').exists() else '缺'} / "
          f"工程级 {'有' if (Path(__file__).parent.parent / 'prompts' / 'project_audit.md').exists() else '缺'}")
    print(f"大模型: {'已配置 ' + c.model if c.available() else '未配置（可先跑 check 命令）'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
