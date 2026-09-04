# 系统总体架构设计（D4）

> 版本 v0.9 ｜ 负责人 杨梦颢 ｜ 与 docs/requirements.md 配套评审

## 1. 设计原则

1. **流程线性、决策点插入**：主链路用确定性编排（申报书 ADR-003），仅在"要不要深入审这个函数"处允许 Agent 式判断（ReAct 预留位）。
2. **静态先行、模型增强**：规则引擎永远先跑——它提供线索（降漏报）、提供校验基准（降误报），也是无密钥时的降级底座。
3. **一切可溯源**：知识条目 ID、CWE 来源、证据原文贯穿每个环节，报告即证据链。
4. **模块间只用数据结构通信**（models.py），不互相 import 内部函数，便于五人并行开发。

## 2. 数据流

```
                    ┌────────────────────────────────────────────┐
                    │                输入适配层                    │
                    │   文件 / 目录 / 代码字符串 / (未来:diff)      │
                    └───────────────────┬────────────────────────┘
                                        ▼
        ①parser.parse_file / split_functions / parse_project
          产出: CodeUnit(kind, name, path, source, 真实行号, context)
                                        │
                ┌───────────────────────┼───────────────────────┐
                ▼                       ▼                       ▼
   ②rules.scan_source        ③retriever.retrieve        (工程级:结构摘要)
     硬性规则命中→线索          代码特征→知识库 top-k
     (零误报底线/降级可用)        (CWE条目+修复要点)
                │                       │
                └───────────┬───────────┘
                            ▼
   ④audit._audit_unit   组装 Prompt: 代码(带行号)+上下文+知识+线索+输出schema
            │            调用 llm.LLMClient（OpenAI 兼容，重试/退避）
            │            解析 extract_json_array → Issue(detector=llm)
                            ▼
   ⑤validate 三道闸门
     check_with_rules: 行号越界? 证据可回溯? → 不可回溯=幻觉, 丢弃并计数
     置信度过滤: <0.5 丢弃; 0.5~0.7 标"待人工确认"   (T2 方案)
     dedupe: 同CWE+行重叠 → 合并为 both, 提升置信度    (T3 方案)
                            ▼
   ⑥report.render_markdown / to_json
     问题清单表 + 逐条详解 + 分类统计 + 引擎元数据
```

## 3. 多粒度调度策略

| 粒度 | 何时用 | 单元切法 | Prompt 侧重 |
|---|---|---|---|
| 函数级 | 默认深审（逐函数调用模型） | AST FunctionDef 含装饰器行 | 局部语义、边界、异常路径 |
| 文件级 | 快审 / 跨函数问题 | 整文件 + 导入/函数清单上下文 | 函数间契约、数据流贯穿 |
| 工程级 | 架构审查（每项目 1 次） | 目录树+每文件结构摘要 | 依赖治理、配置安全、一致性 |

CLI `-d` 选择；`project` 模式 = 工程级 1 次 + 函数级全量。

## 4. 关键机制设计

### 4.1 降误报（申报书关键问题 3）
- 证据回溯校验（已实现：rules.verify）
- 置信度分级（T2，validate.py 待扩展）
- 静态/LLM 交叉印证：both 优先展示，llm 单源降权
- 修复方案自查条款（T1：Prompt 纪律）

### 4.2 降漏报
- 静态线索注入 Prompt（已实现）：但明确告知模型"线索仅供参考"
- 知识库 triggers 检索保证常见模式必被提及
- few-shot 反例（D13）：给"看起来可疑但实际安全"的例子，防模型为凑数乱报

### 4.3 一致性（申报书关键问题 4）
- temperature=0.1 + 输出 schema 强约束 + 模板固定
- `AUDIT_CONSISTENCY_RUNS` ≥ 2 时自动跑 validate.consistency_compare（已实现），结果写入 report.engine
- 目标指标：Jaccard ≥ 0.8（NFR-1）

### 4.4 成本控制
- 函数源码 >400 行时先让模型生成结构摘要再分段审
- 增量缓存（FR-7）：sha256(source+prompt版本+模型名) → 结果
- 每次审计 token 用量写进 out/usage.log，便于额度监控

## 5. 模块依赖关系（单向，禁止环）

```
cli.py → audit.py → {parser, retriever, rules, llm, validate} → models.py
                   ↘ report.py ↗
```
llm.py 不 import 任何业务模块；knowledge/prompts 是纯数据目录，代码只读不写。

## 6. 演进路线

- 第二阶段(10-11月)：向量检索替换 retriever（接口已对齐）、few-shot 库、diff 审计模式
- 第三阶段(12月起)：并发+缓存（T5）、HTML 报告、更多语言
- 结题前：FastAPI 薄封装 CLI，做演示界面（可选项）
