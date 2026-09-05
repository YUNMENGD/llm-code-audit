# 真实库 AI 审计实验（任务A首战 · qwen-plus · flask 全库）

> 日期：2026-09-05 ｜ 对象：flask 24 文件 7569 行（GitHub 16k star 成熟框架）
> 命令：`python -m codeaudit audit ..\realtest\flask\src\flask -d file`
> 成本实测：24 次调用 / 655 秒。token 用量⚠️未实测（usage.log 埋点尚未实现，
> 见 storage-config §5 计划），下方 13 token/行 为按报告体量的粗估，正式数据待补埋点。
> ⚠️ 本实验在 main 上跑，fix/static-probe-fp 的文档串屏蔽当时未合入，个别误报已由其覆盖。

## 结果总览（诚实数据）

AI+静态合并输出 75 条（critical 9 / high 15 / medium 35 / low 16；llm单源67/both5/static3）。
对 24 条 critical+high 做源码级人工核验：**真问题 ≈ 3~4 条，缺陷类 precision 约 15~20%**
——与合成基准上的 0.857 形成断崖差，这就是"清洁小样本高估真实分布"的实证（fp-governance 预测过回落，没想到这么深）。

## 误报模式画像（人工核验 12 条的完整记录）

| 位置 | 报告内容 | 源码事实 | 判定 | 误报模式 |
|---|---|---|---|---|
| templating.py:151/200、__init__.py:35 | render_template_string = SSTI 漏洞 | 框架**公开 API**，文档明示给开发者用，责任在调用方 | ❌ | **A 设计特性当漏洞** |
| app.py:503/711/770/824、scaffold.py:279 | Jinja2 注入 request/g/不可信源 | 模板环境注入应用上下文是 Flask 核心设计 | ❌ | A |
| config.py:209 | from_pyfile exec 远程代码执行 | 执行的是开发者自己的配置文件，官方行为 | ❌(威胁模型夸大) | A |
| ctx.py:232 | `.get` 可空未判空 | 实读为 `return (ctx := _cv_app.get(None)) is not None and ctx.has_re…`——海象+短路完全正确 | ❌ | **B 护栏失明**（只看 API 名不看同行防御） |
| json/tag.py:107/111 | next(iter) StopIteration | check() 已有 `len(value) == 1` 护栏后才 next | ❌ | B |
| config.py:204 | os.path.join 路径遍历 | filename 来自开发者代码调用参数，非外部输入 | ❌ | **C 输入源误判**（无调用方证据仍报高置信） |
| app.py:664 (R-SEC-010) | debug=True 生产暴露 | docstring 里的示例文字 | ❌ | **D 文档残留**（修复分支已屏蔽静态，LLM 侧仍可能犯） |
| cli.py:1023 | eval(compile()) PYTHONSTARTUP | 真实 exec，但对象是本地用户自己的启动脚本，dev CLI 特性 | ⚠️半对 | A 边界 |
| config.py:39 | ConfigAttribute.__get__ 直接下标 | 需人工细核，可能真边界 | ✅ 候选 | — |
| logging.py:52 / views.py:190 / blueprints.py:388 | 分支覆盖不全类 (LOG-011) | Flask 大量 hasattr/getattr 动态分支，模型读不完调用方 | ⚠️ 存疑 | B+C 混合 |

## 核心结论（论文可直接引用的四个层次）

1. **成熟库上的 AI 审计 ≈ 线索生成器，不是判官**：critical 精度 0~11%，medium/low
   多为合理风格建议。工具定位必须写明"辅助复核"，否则答辩会被真实数据反噬。
2. **误报主模式不是"幻觉"而是"上下文缺失的过度推断"**：A(设计特性)和B(护栏失明)
   占约七成——模型看见了危险 API，没看见它是谁、给谁用、有无护栏。这恰是
   申报书"关键问题 2/3"的真实形态，比合成基准的误报更高级，也更有研究价值。
3. **既有防线的拦截率符合设计**：verify 行号校验过滤了 10/85 候选（11.8%），
   但拦不住 B 类（证据行真实存在，只是模型读错了语义）。→ 需要"同行防御表达式"
   识别（海象/短路/len 护栏的 AST 检查）进 verify 层。
4. **成本数据（任务B首份）**：文件级 24 调用/655 秒实测；token 为粗估
   （文件级 ≈13 token/行、函数级 ≈20 token/行，万行库一轮 ≈20 万 token 量级），
   待 usage.log 埋点补正式数字。免费额度支撑 25 库标注集预计无压力。

## 下一步（10 月任务A的改进清单，按误报模式开药方）

- [ ] **治 A**：Prompt 增"框架公开 API/文档明示行为 ≠ 缺陷"纪律；知识库加
      DESIGN-API 类条目（render_template_string、from_pyfile、Jinja env 注入）
- [ ] **治 B**：verify 增加同行防御检测（`:=`、`is not None and`、`len(x)==1 and` 短路护栏）
      复用 _block_reraises 的块感知思路
- [ ] **治 C**：输入源可证性闸门——报"外部可控"类漏洞必须有本文件内
      request/argv/environ 证据行，否则降 LOG 标注为「需人工核查来源」（T2 的强化版）
- [ ] **治 D**：合入 fix/static-probe-fp（AST 文档屏蔽），并把该能力注入 LLM 侧
      （prompt 声明"行号落在字符串内的告警视为无效"——verify 已有证据匹配可捕获大半）
- [ ] 建 flask 手工 ground truth（用本次 24 条的核验结果起步，标注成本已付清一半）
- [ ] 同法跑 httpx/black，凑齐 3 库真实分布数据再定 precision 目标值（0.5? 0.6?）

## 复现

```bash
python -m codeaudit audit <库源码目录> -d file --html out/x.html   # 24文件≈11分钟
# out/flask_report.{md,html,json} 为本次完整产出
```

## 治 B 落地结果（同日，feat/treat-b-guards）

新增两条函数级护栏并接入既有 guard_suppress 管线：
- `G-WALRUS-NOTNONE`：`:= ...get(` / `is not None and` 判空短路
- `G-LEN-SHORTCIRCUIT`：`len(x) == N and ...` 与 `and len(...)` 链式长度校验

**效果（flask 缓存重放）**：75 → 69。但 6 条差异要分开归因（避免错误记功）：

| 归因 | 告警 | 机制 | 是否确定性 |
|---|---|---|---|
| **治 B 护栏**（本分支） | ctx.py:232 LOG-012、tag.py:107 LOG-001 | guard_suppress 直接抑制 | ✅ 重放日志明示"抑制 2 条" |
| **D 模式间接触发**（fix/static-probe-fp 合入的副作用） | app.py 的 664/374/366/216 共 4 条 | AST 文档串屏蔽改变了注入给模型的 hints → app.py prompt 变 → 缓存 miss 重审后模型不再报 | ❌ 依赖模型行为，属"提示净化"而非确定性防线 |

日志证据：首轮重放"命中 22 / 未命中 2"——miss 的正是 app.py 与 config.py；
第二轮起 24/24 全命中（新 prompt 入缓存），结果与首轮一致。

**过度抑制事故与修复**（本实验最有价值的负面记录）：第一版海象 pattern 用了
宽松的 `\bis not None\b`，diff 复核发现 config.py:41 的判空守卫（保护 42 行）
靠行号窗口串位吞掉了 39 行的 `obj.config[...]` KeyError——而 39 行恰是核验表
✅存疑候选，属漏报方向错误。收紧为强制 `is not None and`（判空与使用同表达式
耦合）后串位消失，B2 重放确认 39 行恢复上报。
**教训：护栏 pattern 必须要求防御与危险点表达式级耦合，宽松匹配 + 行号窗口 = 静默漏报。**

回归：106 项测试全绿（含 5 项治 B 专项正反断言）。方法论沉淀：verify/guards 层改动
一律用「旧报告 → 缓存重放 → 集合 diff」三步验证，成本趋零；确定性抑制与模型行为
变化必须分开归因——这套纪律后续推广到 A/C 治理。

## 治 A 落地结果（feat/treat-a-framework-api）

**根因发现（最有价值的产出）**：flask templating.py 那批 SSTI"严重"误报，是我们**自己的
知识库教出来的**——CWE-94 的 triggers 含 `render_template_string`，它同时是该文件里
Flask **定义的函数名**，检索命中就把"此处有 SSTI"当弹药注入 prompt。RAG 的反噬。

**机制**：知识条目新增 `not_when`（适用边界）字段 + retriever 检索层**硬否决**——
某单元命中 not_when 即判定"本文件是该 API 的定义者/框架源码本身"，该 CWE 对它不适用，
检索阶段直接剔除（先试 soft 扣分，实测打不过多 trigger 加分，改 hard veto 才干净）。
作用域天然精准：函数级审单个函数、文件级否决只作用在定义者文件，
另处真用 `render_template_string(user_input)` 的调用方不含 `def` 前缀，照常命中（测试已验）。

**缓存稳定设计**：打分窗口维持 [:3000]、全文只作 veto 的 `scope` 参数——
24 文件重放仅 templating.py 因 prompt 变化重审（1 次计费），其余 23 全命中缓存。
若直接放大打分窗口，会让所有长文件 prompt 变化、缓存全废。

**效果与诚实边界**：critical 9→7。消除的是 templating.py:151/200（定义者场景，确定性）。
**残留 6 条是更难的另一亚类**——app.py 的 `jinja_env.tests/globals[...] = ...`、
scaffold 的 template_folder、__init__ 的 import：这些文件里没有 API 定义行，
是"框架配置自己的模板引擎"，not_when 在原理上覆盖不到。
**刻意停止**：继续给 CWE-94 堆 `jinja_env.tests\[` 等字符串能刷掉它们，但那是
对 flask 过拟合、污染评测公正性，答辩会被"换个框架还work吗"戳穿。正解是另立
DESIGN-API 知识类 + Prompt 纪律"配置框架自身引擎≠漏洞"（治本清单里列为后续项，
需人工核对该判定不吞掉真实的"用不受信源配置 jinja"）。这轮的边界结论本身是成果：
**确定性能治的（定义者）已治，模型过度兴奋的（自配置）留给语义层而非正则硬编码。**
