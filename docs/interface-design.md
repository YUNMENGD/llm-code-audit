# 接口设计文档 ICD（D5）

> 版本 v0.9 ｜ 维护：杨梦颢 ｜ **契约性文档：改函数签名必须先改本文档并 PR 评审**
> 现状标注：✅ 已实现且签名冻结 ｜ 🔧 已实现待迭代 ｜ 📐 仅定义（D13-D17 实现）

## 0. 共享数据结构（codeaudit/models.py）✅

| 类 | 角色 | 关键字段 |
|---|---|---|
| `CodeUnit` | 审计输入单元 | kind(function/file/project), name, path, source, line_start, line_end, context; `.tagged()`→带行号文本 |
| `Issue` | 单条发现 | rule_id, category, severity, title, path, line_start/end, evidence, analysis, impact, fix, confidence, source, detector, verified, votes; `.key()`去重键 |
| `AuditReport` | 一次审计结果 | target, issues, engine(元数据), stats(统计); `.to_json()` |
| `Severity` / `Category` | 枚举 | critical/high/medium/low ｜ security/logic/style/engineering |
| `ISSUE_JSON_SCHEMA` | LLM 输出约束 | 写进 Prompt 的 JSON schema |

## 1. parser ✅

```python
parse_project(root: str|Path) -> CodeUnit        # 目录树+文件摘要，kind="project"
parse_file(path: str|Path) -> CodeUnit           # 单文件，kind="file"，context含imports/functions/doc
split_functions(unit: CodeUnit) -> list[CodeUnit] # file→N个function单元，真实行号
parse_sources(source: str, name: str) -> list[CodeUnit]  # 字符串→[file, *functions]
IGNORE_DIRS: set[str]                             # 遍历排除目录
```
约定：行号一律 **1-based 含端点**；装饰器归入函数单元；SyntaxError 文件降级为整体单元不抛异常。
🔧 D14 扩展：`parse_file_java()` 等经 tree-sitter，返回同一 CodeUnit，调用方无感知。

## 2. rules ✅

```python
load_rules() -> list[dict]                       # 聚合 knowledge/rules/*.json
scan_source(source: str, rules, path) -> list[Issue]   # 正则命中→Issue(detector=static, verified=True)
verify(issue: Issue, source_lines) -> tuple[bool, str] # 行号存在? 证据可回溯?
```
规则 JSON schema（knowledge/rules/hard_rules.json）：
```json
{"id":"R-SEC-001","title":"...","category":"security","severity":"critical",
 "source":"CWE-89 https://...","pattern":"正则","exclude":["# nosec"],
 "why":"...","impact":"...","suggestion":"..."}
```
📐 D15 新增 `knowledge/rules/cwe_map.json`：`{"R-SEC-001":"CWE-89", ...}` 供 T3 合并用。

## 3. retriever ✅关键词版

```python
load_knowledge() -> list[dict]
retrieve(query: str, top_k=5, items=None) -> list[dict]   # 打分排序，返回带 score
format_for_prompt(results) -> str                          # 渲染成知识区块（含ID+来源）
```
知识条目 schema（knowledge/defects/*.json 的 items[]）：
```json
{"id":"CWE-89","title":"SQL注入","category":"security","severity":"critical",
 "tags":[...],"triggers":[...],"pattern":"...","impact":"...","fix":"...","source":"链接"}
```
📐 D12 换向量版：**签名不变**，新增向量索引缓存目录 `data/vec/`（已 gitignore），降级时自动回退关键词打分。

## 4. llm ✅

```python
class LLMClient:
    available() -> bool                          # 无 Key 返回 False，不抛错
    chat(messages, temperature=None) -> str      # 重试+指数退避；失败抛 LLMError
extract_json_array(text) -> list[dict]           # 容错抠 JSON（围栏/废话/转义）
```
📐 扩展队列：`chat_json()`（response_format json_object 模式，模型支持时）、
token 计量返回、embedding 封装 `embed(texts)->list[list[float]]`（D12 用）。

## 5. audit（杨梦颢）✅

```python
audit_path(target: str|Path, depth="function"|"file"|"project") -> AuditReport  # 唯一编排入口
load_prompt(name) -> str                         # prompts/{name} 读取
```
约定：模型不可用时静默降级只跑静态；单单元 LLM 失败不影响其余单元（warn 后继续）。
📐 T5：内部并发池 + `audit_changed(since_commit)` 增量入口（12 月）。

## 6. validate（杨梦颢）✅基础

```python
check_with_rules(issue, source_lines) -> tuple[bool, str]
dedupe(issues) -> list[Issue]
consistency_compare(reports: list[list[Issue]]) -> dict  # {"runs","avg_pairwise","stable_rules"}
```
📐 D15 扩展（T2/T3）：
```python
confidence_gate(issues, drop=0.5, review=0.7) -> list[Issue]   # 过滤+标注
cwe_merge(issues, cwe_map) -> list[Issue]                       # 跨来源同CWE同行段合并
```

## 7. report ✅

```python
render_markdown(r: AuditReport) -> str
write_report(r, out_md, out_json=None) -> tuple[Path, Path|None]
load_report_json(path) -> dict                   # 复跑 diff / 一致性对比用
```
📐 D16 扩展：`render_html(r)`（markdown 库直转）、修复建议 code fence 规范化（T4：`\n` 还原+ast.parse 失败降级为纯文本）。

## 8. CLI（杨梦颢）✅

```
python -m codeaudit check  <路径>                      # 免密钥静态
python -m codeaudit audit  <路径> [-d 粒度] [-o md] [-j json]
python -m codeaudit rules | kb <词> [-n N] | selfcheck
```
退出码：check 发现 critical/high → 1（供未来 CI 卡点），其余 0。

## 9. 数据文件与目录契约

| 路径 | 写权限归属 | 说明 |
|---|---|---|
| knowledge/** | PR 评审制，全员可提，负责人合并 | 新增条目必须带 source |
| prompts/** | 负责人合并；模板 `{{var}}` 由 audit 渲染，变量名冻结：language/scope/context/knowledge/hints/code |
| out/** , data/** | 运行时产物 | 永不入库 |
| docs/** | 全员 | 设计变更同步修订本文档 |

## 10. 变更流程

改任何 ✅ 签名 = 破坏性变更：开 Issue 说明动机 → PR 同时更新本文档与 tests → 至少 1 人 review。
