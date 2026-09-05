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
