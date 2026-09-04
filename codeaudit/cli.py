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
            s.add_argument("--cross-review", dest="cross", action="store_true",
                           default=None,
                           help="启用 D15 双模型交叉复核（需配置 LLM2_API_KEY；两模型串行调用，耗时约翻倍）")

    sub.add_parser("rules", help="列出规则库")
    k = sub.add_parser("kb", help="检索知识库")
    k.add_argument("query")
    k.add_argument("-n", type=int, default=5)
    sub.add_parser("selfcheck", help="环境自检")

    a = ap.parse_args(argv)

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

    if a.cmd == "check":
        from .report import render_markdown
        from .models import AuditReport
        files = [Path(a.target)] if Path(a.target).is_file() else sorted(
            p for p in Path(a.target).rglob("*.py")
            if not any(x in p.parts for x in P.IGNORE_DIRS))
        all_rules = RL.load_rules()
        issues = []
        for f in files:
            issues += RL.scan_source(f.read_text(encoding="utf-8", errors="replace"),
                                     all_rules, str(f))
        rep = AuditReport(target=a.target, issues=issues,
                          engine={"model": "static-only", "llm_used": False,
                                  "units": len(files), "rules_loaded": len(all_rules),
                                  "knowledge_loaded": len(R.load_knowledge())},
                          stats={"total": len(issues),
                                 "by_severity": {}, "by_category": {}, "by_detector": {}})
        rep.stats["by_severity"] = rep.count_by("severity")
        rep.stats["by_category"] = rep.count_by("category")
        print(render_markdown(rep))
        return 1 if any(i.severity.value in ("critical", "high") for i in issues) else 0

    # audit
    from .audit import audit_path
    from .report import write_report
    print(f"审计 {a.target}（粒度 {a.depth}）...")
    rep = audit_path(a.target, depth=a.depth, use_examples=a.examples,
                     cross_review=a.cross)
    md, js, hp = write_report(rep, a.out, a.json_out, a.html_out)
    extra = f"、{hp}" if hp else ""
    print(f"完成：{rep.stats['total']} 个问题 → {md}{extra}")
    cr = rep.stats.get("cross_review") or {}
    if cr.get("enabled"):
        print(f"交叉复核：共识 {cr['agreed']} / 单源待确认 {cr['single_model']}"
              f" / 一致率 {cr['agreement_rate']}")
    if not rep.engine["llm_used"]:
        print("提示：未检测到大模型 API Key，本次仅静态规则结果。配置 .env 后可获得语义级审计。")
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
