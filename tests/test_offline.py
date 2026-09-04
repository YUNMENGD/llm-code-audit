"""离线单元测试（不需要 API Key，CI 可跑）。

运行：python tests/test_offline.py
覆盖：parser 切分、rules 命中与豁免、retriever 检索、validate 校验与去重、
     models 解析容错、report 渲染、一致性统计。
"""
from __future__ import annotations

import os
os.environ["RAG_VECTOR"] = "0"    # 离线测试固定关键词路径，保证不联网不耗额度

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codeaudit import parser as P                    # noqa: E402
from codeaudit import report as RP                   # noqa: E402
from codeaudit import retriever as RT                # noqa: E402
from codeaudit import rules as RL                    # noqa: E402
from codeaudit import validate as VD                 # noqa: E402
from codeaudit.llm import extract_json_array         # noqa: E402
from codeaudit.models import AuditReport, Category, Issue, Severity  # noqa: E402

SAMPLE = (Path(__file__).resolve().parent.parent / "examples" / "vulnerable_app.py").read_text(encoding="utf-8")
PASS = 0


def check(name: str, cond: bool):
    global PASS
    print(f"  {'✓' if cond else '✗'} {name}")
    if not cond:
        raise SystemExit(f"测试失败：{name}")
    PASS += 1


print("[1] parser：AST 切分")
fu = P.parse_file(Path("examples/vulnerable_app.py"))
check("文件级单元行号正确", fu.line_end == len(SAMPLE.splitlines()))
funcs = P.split_functions(fu)
names = {f.name for f in funcs}
check("函数切分完整", {"get_user", "export_report", "find_max", "calc"} <= names)
f1 = next(f for f in funcs if f.name == "get_user")
SQL_LINE = next(i for i, l in enumerate(SAMPLE.splitlines(), 1) if "cur.execute" in l)
check("函数带真实行号", f1.line_start == SQL_LINE - 3 and f1.source.startswith("def get_user"))
check("行号标注可渲染", f"{f1.line_start}|" in f1.tagged())
proj = P.parse_project(Path("codeaudit"))
check("工程级摘要含目录树", proj.kind == "project" and "parser.py" in proj.source)

print("[2] rules：静态命中")
rs = RL.load_rules()
check("规则库加载", len(rs) >= 10)
hits = RL.scan_source(SAMPLE, rs, "examples/vulnerable_app.py")
ids = {h.rule_id for h in hits}
check("命中 SQL 注入", "R-SEC-001" in ids)
check("命中命令注入", "R-SEC-002" in ids)
check("命中 eval", "R-SEC-003" in ids)
check("命中 pickle", "R-SEC-004" in ids)
check("命中硬编码密钥", "R-SEC-006" in ids)
check("命中裸except", "R-LOG-001" in ids)
check("命中可变默认参数", "R-LOG-002" in ids)
check("命中弱哈希", "R-SEC-007" in ids)
check("静态结果默认已校验", all(h.verified for h in hits))
ok, _ = VD.check_with_rules(hits[0], SAMPLE.splitlines())
check("静态命中可通过回溯校验", ok)

print("[3] rules：豁免与误报控制")
safe = 'cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))'
check("参数化查询不误报", not any(h.rule_id == "R-SEC-001" for h in RL.scan_source(safe, rs)))
check("注释豁免生效", not any(h.rule_id == "R-SEC-002" for h in RL.scan_source('os.system("ls")  # nosec', rs)))

print("[4] retriever：知识库检索")
kb = RT.load_knowledge()
check("知识库加载", len(kb) >= 20)
top = RT.retrieve("cur.execute(f'SELECT * FROM users WHERE id = {user_id}')", items=kb)
check("检索命中 SQL 注入知识", top and top[0]["id"] == "CWE-89")
blk = RT.format_for_prompt(top)
check("Prompt 片段含来源标注", "https://cwe.mitre.org" in blk)

print("[5] validate：模型结果三道闸门")
good = Issue(rule_id="CWE-89", category=Category.SECURITY, severity=Severity.CRITICAL,
             title="SQL注入", path="p.py", line_start=18,
             evidence="cur.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
             analysis="a", fix="b", detector="llm")
bad_line = Issue(rule_id="X", category=Category.LOGIC, severity=Severity.LOW,
                 title="t", path="p.py", line_start=99999, evidence="", analysis="", fix="")
bad_ev = Issue(rule_id="Y", category=Category.LOGIC, severity=Severity.LOW,
               title="t", path="p.py", line_start=18, evidence="这行代码根本不存在", analysis="", fix="")
check("有效报告通过校验", VD.check_with_rules(good, SAMPLE.splitlines())[0])
check("行号越界被拦截", not VD.check_with_rules(bad_line, SAMPLE.splitlines())[0])
check("伪造证据被拦截", not VD.check_with_rules(bad_ev, SAMPLE.splitlines())[0])
merged = VD.dedupe([good, good])
check("同行同规则去重", len(merged) == 1 and merged[0].votes == 2)
both = VD.dedupe([hits[0], Issue(rule_id=hits[0].rule_id, category=hits[0].category,
                                 severity=hits[0].severity, title="t", path=hits[0].path,
                                 line_start=hits[0].line_start, evidence="", analysis="",
                                 fix="", detector="llm")])
check("静态+模型合并为 both", len(both) == 1 and both[0].detector == "both")
cs = VD.consistency_compare([[good, bad_line], [good], [good, bad_line]])
check("一致性指标可计算", cs["runs"] == 3 and "CWE-89" in cs["stable_rules"])

print("[5b] T2/T3 新闸门")
lo = Issue(rule_id="CWE-999", category=Category.LOGIC, severity=Severity.LOW, title="t",
           path="p", line_start=2, evidence="", analysis="a", fix="f",
           confidence=0.3, detector="llm")
mid = Issue(rule_id="CWE-998", category=Category.SECURITY, severity=Severity.HIGH, title="t",
            path="p", line_start=3, evidence="", analysis="a", fix="f",
            confidence=0.6, detector="llm")
static = hits[1]                      # hits[0] 已被上面的合并用例原地改写为 both
gated = VD.confidence_gate([good, lo, mid, static])
check("低置信LLM结果被丢弃", lo not in gated)
check("中置信结果保留并标注", any(i.rule_id == "CWE-998" and i.analysis.startswith(VD.REVIEW_MARK) for i in gated))
check("静态结果不受闸门影响", any(i.detector == "static" for i in gated))
s1 = Issue(rule_id="R-SEC-002", category=Category.SECURITY, severity=Severity.CRITICAL,
           title="os.system 执行外部命令", path="p2.py", line_start=26,
           evidence="os.system(x)", analysis="简", fix="f",
           confidence=0.95, detector="static", verified=True)
llm_same_cwe = Issue(rule_id="CWE-78", category=Category.SECURITY, severity=Severity.CRITICAL,
                     title="命令注入", path="p2.py", line_start=26,
                     evidence="os.system(x)", analysis="详细的数据流论证" * 10,
                     fix="subprocess 列表参数", confidence=0.95, detector="llm", verified=True)
merged3 = VD.cwe_merge([s1, llm_same_cwe])
check("同CWE跨来源合并为1条", len(merged3) == 1 and merged3[0].detector == "both")
check("合并保留富文本分析", "数据流论证" in merged3[0].analysis)
far = Issue(rule_id="CWE-89", category=Category.SECURITY, severity=Severity.CRITICAL,
            title="另一处SQL注入", path="p", line_start=900, line_end=902,
            evidence="", analysis="a", fix="f", detector="llm")
check("行号不重叠不合并", len(VD.cwe_merge([llm_same_cwe, far])) == 2)
noisy = Issue.from_dict({"rule_id": "X", "category": "logic", "severity": "low", "title": "t",
                         "line_start": 1, "evidence": "a\\nb", "analysis": "c",
                         "fix": "def f():\\n    return 1", "confidence": 0.9}, path="p")
check("字面转义符被还原(T4)", "\n" in noisy.fix and "\\n" not in noisy.fix)

print("[5c] rule_id 白名单闸门")
valid = {it["id"] for it in RT.load_knowledge()} | {r["id"] for r in RL.load_rules()}
wrong = Issue(rule_id="CWE-5021", category=Category.SECURITY, severity=Severity.HIGH,
              title="错引ID", path="p", line_start=5, evidence="", analysis="a", fix="f",
              confidence=0.9, detector="llm")
right = Issue(rule_id="CWE-89", category=Category.SECURITY, severity=Severity.CRITICAL,
              title="正确ID", path="p", line_start=6, evidence="", analysis="a", fix="f",
              confidence=0.9, detector="llm")
disc = Issue(rule_id="DISCOVERED-1", category=Category.LOGIC, severity=Severity.MEDIUM,
             title="模型自编号", path="p", line_start=7, evidence="", analysis="a", fix="f",
             confidence=0.9, detector="llm")
st_bad = Issue(rule_id="NOT-IN-KB", category=Category.STYLE, severity=Severity.LOW,
               title="静态乱ID", path="p", line_start=8, evidence="", analysis="a", fix="f",
               detector="static")
gated2 = VD.rule_id_gate([wrong, right, disc, st_bad], valid)
w2 = next(x for x in gated2 if x.line_start == 5)
check("未知rule_id被纠正", w2.rule_id.startswith("DISCOVERED-CWE-5021") and "已纠正" in w2.analysis)
check("知识库已有ID放行", next(x for x in gated2 if x.line_start == 6).rule_id == "CWE-89")
check("模型自编号DISCOVERED放行", next(x for x in gated2 if x.line_start == 7).rule_id == "DISCOVERED-1")
check("静态结果不纠正", next(x for x in gated2 if x.line_start == 8).rule_id == "NOT-IN-KB")
check("空ID集合时全部放行", len(VD.rule_id_gate([wrong, right], set())) == 2)

print("[6] llm 输出解析容错")
check("裸 JSON", len(extract_json_array('[{"a":1}]')) == 1)
check("围栏 JSON", len(extract_json_array('```json\n[{"a":1},{"b":2}]\n```')) == 2)
check("带废话前缀", len(extract_json_array('好的：\n[{"x":[1,2]}]\n以上')) == 1)
check("字符串内含括号", len(extract_json_array('[{"s":"a]b["},{"t":2}]')) == 2)
check("非法 JSON 返回空", extract_json_array('[{"broken":') == [])
i = Issue.from_dict({"rule_id": "C", "category": "SECURITY!", "severity": "critical",
                     "title": "x", "line_start": "12", "confidence": 1.7,
                     "evidence": "e", "analysis": "a", "fix": "f"}, path="p")
check("枚举大小写容错", i.category == Category.LOGIC)          # 非法值→默认
check("行号字符串容错", i.line_start == 12)
check("置信度截断", i.confidence == 1.0)

print("[7] report：渲染")
rep = AuditReport(target="p", issues=[good], engine={"model": "m", "llm_used": False, "units": 1},
                  stats={"total": 1, "by_severity": {"critical": 1}, "by_category": {}, "by_detector": {}, "elapsed_sec": 0})
md = RP.render_markdown(rep)
check("报告含标题与概览", "# 代码审计报告" in md and "critical" in md.lower() or "严重" in md)
check("报告含定位与修复", "p.py:18" in md and "修复建议" in md)
js = rep.to_json()
check("JSON 可往返", '"rule_id": "CWE-89"' in js)

print(f"\n全部通过：{PASS} 项 ✓")
