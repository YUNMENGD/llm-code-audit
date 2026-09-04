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

print("\n[8] examples：few-shot 校准示例（D13）")
from codeaudit import examples as EX                 # noqa: E402
from codeaudit import audit as AU                     # noqa: E402
fn_ex = EX.format_examples("function")
check("函数级示例含多例", "## 示例1" in fn_ex and "## 示例2" in fn_ex)
check("含 SQL 注入正例", "CWE-89" in fn_ex and "参数化" in fn_ex)
check("含参数化查询反例", "WHERE name=%s" in fn_ex)
file_ex = EX.format_examples("file")
check("文件级含跨函数数据流例", "CWE-22" in file_ex and "read_req" in file_ex)
check("limit 截断示例数", EX.format_examples("function", limit=1).count("## 示例") == 1)
check("开关：显式 True", EX.examples_enabled(True) is True)
check("开关：显式 False", EX.examples_enabled(False) is False)
os.environ["PROMPT_EXAMPLES"] = "0"
check("开关：读环境变量=0", EX.examples_enabled() is False)
os.environ["PROMPT_EXAMPLES"] = "1"
check("开关：读环境变量=1", EX.examples_enabled() is True)
del os.environ["PROMPT_EXAMPLES"]

tpl_fn = AU.load_prompt("function_audit.md")
check("函数模板含 examples 占位符", "{{examples}}" in tpl_fn)
check("函数示例不再内联硬编码", tpl_fn.count("cur.execute") == 0)
tpl_file = AU.load_prompt("file_audit.md")
check("文件模板含 examples 占位符", "{{examples}}" in tpl_file)

print("\n[9] validate：双模型交叉复核（D15）")
m_agree = Issue(rule_id="CWE-89", category=Category.SECURITY, severity=Severity.CRITICAL,
                title="t", path="p", line_start=10, evidence="", analysis="共识x", fix="f",
                detector="llm", votes=2, models=["qwen-plus", "deepseek-v4-flash"])
m_only = Issue(rule_id="CWE-22", category=Category.SECURITY, severity=Severity.HIGH,
               title="t2", path="p", line_start=20, evidence="", analysis="单源y", fix="f",
               detector="llm", votes=1, models=["qwen-plus"])
m_static = Issue(rule_id="R-SEC-002", category=Category.SECURITY, severity=Severity.CRITICAL,
                 title="t3", path="p", line_start=30, evidence="", analysis="z", fix="f",
                 detector="static")
cr = VD.cross_review([m_agree, m_only, m_static], enabled=True, n_models=2)
check("共识计数", cr["agreed"] == 1)
check("单源计数", cr["single_model"] == 1)
check("一致率计算", cr["agreement_rate"] == 0.5)
check("单源被标注待确认", m_only.analysis.startswith(VD.REVIEW_MARK))
check("共识项不被标注", m_agree.analysis == "共识x")
check("静态项不被标注", m_static.analysis == "z")
check("关闭时返回enabled=False", VD.cross_review([], enabled=False) == {"enabled": False})
mm1 = Issue(rule_id="CWE-89", category=Category.SECURITY, severity=Severity.CRITICAL,
            title="a", path="p9.py", line_start=5, evidence="e", analysis="A" * 40,
            fix="f", detector="llm", models=["qwen"])
mm2 = Issue(rule_id="R-SEC-001", category=Category.SECURITY, severity=Severity.CRITICAL,
            title="b", path="p9.py", line_start=5, evidence="e", analysis="B",
            fix="f", detector="llm", models=["deepseek"])
mg = VD.cwe_merge([mm1, mm2])
check("双模型同CWE合并为cross", len(mg) == 1 and mg[0].detector == "cross"
      and len(mg[0].models) == 2)
mm3 = Issue(rule_id="CWE-89", category=Category.SECURITY, severity=Severity.CRITICAL,
            title="c", path="p9b.py", line_start=5, evidence="e", analysis="A",
            fix="f", detector="llm", models=["qwen"])
mm4 = Issue(rule_id="CWE-89", category=Category.SECURITY, severity=Severity.CRITICAL,
            title="d", path="p9b.py", line_start=5, evidence="e", analysis="B",
            fix="f", detector="llm", models=["qwen"])
check("同模型重复不合并", len(VD.cwe_merge([mm3, mm4])) == 2)
m_both2 = Issue(rule_id="R-SEC-001", category=Category.SECURITY, severity=Severity.CRITICAL,
                title="三方印证", path="pc.py", line_start=1, evidence="e", analysis="x",
                fix="f", detector="both", votes=3, models=["qwen", "deepseek"])
m_both1 = Issue(rule_id="R-SEC-002", category=Category.SECURITY, severity=Severity.CRITICAL,
                title="规则+单模型", path="pc.py", line_start=2, evidence="e", analysis="y",
                fix="f", detector="both", votes=2, models=["qwen"])
m_lone = Issue(rule_id="CWE-22", category=Category.SECURITY, severity=Severity.HIGH,
               title="孤证", path="pc.py", line_start=3, evidence="e", analysis="z",
               fix="f", detector="llm", models=["qwen"])
cr2 = VD.cross_review([m_both2, m_both1, m_lone], enabled=True, n_models=2)
check("both+双模型计入共识", cr2["agreed"] == 1)
check("both+单模型算规则背书", cr2["confirmed_by_rule"] == 1 and not m_both1.analysis.startswith(VD.REVIEW_MARK))
check("纯llm孤证才被标注", m_lone.analysis.startswith(VD.REVIEW_MARK))
check("一致率分母含孤证", cr2["agreement_rate"] == 0.5)
nd_q = Issue(rule_id="CWE-95", category=Category.SECURITY, severity=Severity.CRITICAL,
             title="eval", path="pn.py", line_start=9, evidence="e", analysis="A" * 30,
             fix="f", detector="llm", models=["qwen"])
nd_d = Issue(rule_id="DISCOVERED-CWE-95-02", category=Category.SECURITY,
             severity=Severity.CRITICAL, title="eval2", path="pn.py", line_start=9,
             evidence="e", analysis="B", fix="f", detector="llm", models=["deepseek"])
nd_m = VD.cwe_merge([nd_q, nd_d])
check("DISCOVERED-CWE-x 键归一可合并", len(nd_m) == 1 and len(nd_m[0].models) == 2)
check("Issue默认models为空", Issue(rule_id="X", category=Category.LOGIC, severity=Severity.LOW,
                                  title="t", path="p", line_start=1, evidence="",
                                  analysis="", fix="").models == [])
_i = Issue.from_dict({"rule_id": "CWE-89", "category": "security", "severity": "high",
                      "title": "t", "line_start": 1, "evidence": "e",
                      "analysis": "a", "fix": "f", "confidence": 0.9},
                     path="p", model="qwen-plus")
check("from_dict写入models", _i.models == ["qwen-plus"])

print("\n[10] report：HTML 渲染（D16）")
html = RP.render_html(rep)
check("HTML 含文档结构", "<!doctype html>" in html and "代码审计报告" in html)
check("HTML 表格已渲染", "<table>" in html and "CWE-89" in html)
check("HTML 内嵌样式", "<style>" in html and "border-collapse" in html)
check("cross 检出方式有映射", RP._DET.get("cross") == "双模型共识")

print("\n[11] cache：增量缓存与并发（D17）")
import shutil                       # noqa: E402
import tempfile                     # noqa: E402
from codeaudit import cache as CH    # noqa: E402

_tmpdir = Path(tempfile.mkdtemp())
_old_file = CH.CACHE_FILE
CH.CACHE_FILE = _tmpdir / "cache.json"
CH._MEM = None
k1 = CH.cache_key("prompt-a", "model-x")
check("缓存键稳定且区分模型", CH.cache_key("prompt-a", "model-x") == k1
      and CH.cache_key("prompt-a", "model-y") != k1)
check("初始未命中", CH.get(k1) is None)
CH.put(k1, "RAW-OUTPUT", model="model-x")
check("put 后命中", CH.get(k1) == "RAW-OUTPUT")
CH.flush()
CH._MEM = None
check("落盘重启仍命中", CH.get(k1) == "RAW-OUTPUT")
check("开关默认开", CH.enabled() is True)
os.environ["AUDIT_CACHE"] = "0"
check("环境变量可关", CH.enabled() is False)
del os.environ["AUDIT_CACHE"]
check("显式参数优先于环境", CH.enabled(True) is True)

check("并发度不超任务数", AU._concurrency(1) == 1)
check("并发度上限10", AU._concurrency(100) <= 10)


class _FakeLLM:
    model = "fake-model"

    def __init__(self):
        self.calls = 0

    def available(self):
        return True

    def chat(self, messages, temperature=None):
        self.calls += 1
        return ('[{"rule_id":"CWE-89","category":"security","severity":"high",'
                '"title":"SQL注入","line_start":19,"line_end":19,'
                '"function_name":"get_user",'
                '"evidence":"cur.execute(f\\"SELECT * FROM users WHERE id = {user_id}\\")",'
                '"analysis":"a","impact":"i","fix":"参数化","confidence":0.9}]')


get_user_unit = next(f for f in funcs if f.name == "get_user")
fake = _FakeLLM()
res1, hit1 = AU._audit_unit(fake, get_user_unit, fu.source.splitlines(),
                            rs, RT.load_knowledge(), False, True)
check("首次未命中缓存并调模型", hit1 is False and fake.calls == 1)
check("返回契约 (issues, hit)", len(res1) == 1 and res1[0].rule_id == "CWE-89")
res2, hit2 = AU._audit_unit(fake, get_user_unit, fu.source.splitlines(),
                            rs, RT.load_knowledge(), False, True)
check("二次命中缓存不再调用", hit2 is True and fake.calls == 1)
check("缓存重放结果一致", len(res2) == 1 and res2[0].title == res1[0].title)
res3, hit3 = AU._audit_unit(fake, get_user_unit, fu.source.splitlines(),
                            rs, RT.load_knowledge(), False, False)
check("关缓存则永远调模型", hit3 is None and fake.calls == 2)

CH.CACHE_FILE = _old_file
CH._MEM = None
shutil.rmtree(_tmpdir, ignore_errors=True)

print("\n[12] guards：防护抑制（D19 误报治理）")
src_g = ("import yaml\n"
         "with open(p) as f:\n"
         "    data = yaml.safe_load(f)\n"
         "x = 1\ny = 2\nz = 3\nw = 4\nv = 5\nu = 6\n"
         "pickle.loads(other)\n")
cov = RL.guard_coverage(src_g)
check("safe_load 防护点被定位", 3 in cov.get("CWE-502", set()))
g502_near = Issue(rule_id="CWE-502", category=Category.SECURITY, severity=Severity.CRITICAL,
                  title="yaml", path="a.py", line_start=2, line_end=3, evidence="e",
                  analysis="a", fix="f", confidence=0.9, detector="llm")
g502_far = Issue(rule_id="CWE-502", category=Category.SECURITY, severity=Severity.CRITICAL,
                 title="pickle", path="a.py", line_start=10, evidence="e",
                 analysis="a", fix="f", confidence=0.9, detector="llm")
keep, supp = VD.guard_suppress([g502_near, g502_far], {"a.py": cov})
check("防护点附近告警被抑制", keep == [g502_far] and len(supp) == 1)
keep2, _ = VD.guard_suppress([g502_near], {"other.py": cov})
check("跨文件不串位", keep2 == [g502_near])
st = Issue(rule_id="CWE-502", category=Category.SECURITY, severity=Severity.CRITICAL,
           title="s", path="a.py", line_start=3, evidence="e", analysis="a", fix="f",
           detector="static", verified=True)
keep3, _ = VD.guard_suppress([st], {"a.py": cov})
check("静态告警不受抑制", keep3 == [st])
check("真实 guards 可加载", len(RL.load_guards()) >= 7)

print(f"\n全部通过：{PASS} 项 ✓")
