# 污点追踪真实库量化实验

- 日期：2026-11-12
- 对象：bench-real 同款六个真实开源库（botocore/click/flask/requests/trio/werkzeug）
- 口径：precision = T/(T+F)；**v5 治理后 1.0（5/5 候选全 T）**；治理前基线 0.417（T=5 / F=7 / ?=0，下表为完整标注基线）
- 口径：precision = T/(T+F) = **0.417**（T=5 / F=7 / ?=0，? 单列不计入）

> 候选路径是静态近似「提示」而非裁决：分层架构中静态层给证据、LLM 层做语义裁决。
> 本指标度量证据层噪声水平，与 bench-real 告警 precision 口径一致。

## 分库明细

| 库 | T | F | ? | precision |
| --- | --- | --- | --- | --- |
| flask | 4 | 0 | 0 | 1.0 |
| trio | 0 | 4 | 0 | 0.0 |
| werkzeug | 1 | 3 | 0 | 0.25 |

## 分 sink 明细

| sink | T | F | ? |
| --- | --- | --- | --- |
| open | 3 | 4 | 0 |
| eval | 1 | 0 | 0 |
| exec | 1 | 0 | 0 |
| frame.eval | 0 | 1 | 0 |
| send_file | 0 | 1 | 0 |
| self.open | 0 | 1 | 0 |

## 误报模式归纳

- TYPE: 3 条
- CONST: 2 条
- CLI: 2 条

## v5 精度治理前后对照（同一标注基线）

- 治理规则：四条通用治理（非针对个案）：①open/eval/exec 只认裸内置调用（末段名判定，builtins. 显式前缀豁免）②send_file(BytesIO/StringIO) 内存对象非路径过滤 ③赋值文本字符串遮蔽后判外部特征 + __file__ 派生常量不染色 ④parse_args 派生变量记 CLI 信任色并传播，纯 CLI 流默认过滤（AUDIT_TAINT_CLI=1 可保留）

| 口径 | 候选数 | T | F | precision |
| --- | --- | --- | --- | --- |
| 治理前 | 12 | 5 | 7 | 0.417 |
| 治理后 | 5 | 5 | 0 | 1.0 |

- 零丢失校验：治理前后 T 候选集合完全一致（5/5 保留），被滤除的 7 条全部为此前核验的 F；过滤计数透明入 stats（filtered_bare/const/cli/buffer）
- 诚实口径：小样本（12→5）上的治理效果，不外推为任意代码库的 precision；标注基线固化可复核
- 复现：治理后重跑 `--collect` 得 5 条候选，与标注中 5 条 T 的位置逐一吻合；被滤除候选的过滤计数见各库 stats（filtered_*）

## 核验标注全文

| 库 | 位置 | sink | 判定 | 依据 |
| --- | --- | --- | --- | --- |
| flask | cli.py:1023 | eval | T | PYTHONSTARTUP 环境变量→读取文件→eval 执行，流真实；解释器启动脚本兼容是文档化设计，信任边界=本地环境 |
| flask | cli.py:1022 | open | T | 环境变量控制打开路径，流真实；isfile 校验存在性但不约束目录，属同一设计特性 |
| flask | config.py:209 | exec | T | from_envvar 环境变量→from_pyfile→exec 配置文件，跨函数传播真实；加载开发者指定配置是框架设计 |
| flask | config.py:208 | open | T | 同上链路：root_path join 环境变量文件名后 open，流真实 |
| trio | _tests/check_type_completeness.py:222 | open | F | errors_by_platform_file 由 Path(__file__).parent/常量名构成，非外部输入；.exists() 文本撞外部特征正则致误染 |
| trio | _tests/check_type_completeness.py:181 | open | F | 同变量同误染：仓库内固定 JSON 路径 |
| trio | _tools/mypy_annotate.py:121 | open | F | cmd_line.dumpfile 是开发者自有 CLI 参数，写自己指定的结果文件；本地工具自有输入不构成攻击面 |
| trio | _tools/mypy_annotate.py:102 | open | F | 同上：读自有 dumpfile，信任边界=运行工具的人 |
| werkzeug | debug/__init__.py:398 | frame.eval | F | frame.eval 是调试器帧求值方法而非内置 eval；目录后缀匹配过宽，且调试控制台有 PIN+host 信任护栏 |
| werkzeug | debug/__init__.py:431 | send_file | F | send_file 首参是 BytesIO 内存对象而非路径，download_name 仅建议文件名；路径遍历不适用 |
| werkzeug | test.py:1064 | self.open | F | 测试客户端 self.open 发模拟请求，builder 是请求构造器非文件路径；方法名撞 open 目录 |
| werkzeug | utils.py:490 | open | T | send_file 的 path 参数→open，调用方可传请求派生路径，流真实；safe_join 校验是调用方责任（文档化），提示有价值 |
