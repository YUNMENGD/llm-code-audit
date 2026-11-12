# 污点追踪真实库量化实验

- 日期：2026-11-12
- 对象：bench-real 同款六个真实开源库（botocore/click/flask/requests/trio/werkzeug）
- 方法：TaintTracker（source/sink 目录 + 调用图迭代传播）产出候选路径，逐条读源码上下文人工核验 T（真实数据流）/ F（近似误报）/ ?（存疑）
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
