# 基于大语言模型的代码审计系统（llm-code-audit）

> 西安工业大学 · 国家级大学生创新训练计划项目
> 项目负责人：杨梦颢 ｜ 指导教师：喻钧

利用大语言模型的语义理解与逻辑推理能力，结合 RAG（检索增强生成）、静态规则引擎与
工作流编排，对代码进行**工程级 / 文件级 / 函数级**多粒度审计：识别安全漏洞、逻辑错误、
规范问题，经规则校验与交叉复核后，输出带定位信息和修复建议的结构化审计报告。

**15 条静态规则 · 61 条缺陷知识 · 6 个真实开源库 125 条人工核验标注 · 零真缺陷误杀红线**

## 分层降噪架构

在成熟开源库上，"报得多"不是能力，噪声才是天花板。本系统以**确定性静态层在前、
概率性 LLM 层在后**的分层设计逐层压缩误报，每一层效果均可量化：

```
代码输入 ──▶ parser（AST 解析/切分）
                │
    ① 静态规则引擎：15 条硬规则 + 误报模式治理（字符串遮蔽/探测惯用法/资源管理/
    │     方法名撞车/协议哈希/noqa…）——零成本、逐字节可复现
    │
    ② RAG 知识检索：61 条缺陷知识（CWE 来源标注）按需注入 Prompt
    │
    ③ LLM 分析：函数/文件/工程三级模板
    │
    ④ validate（行号锚定校验/去重/双模型交叉复核/防护抑制）
    │
    └─▶ report（Markdown / HTML / 桌面端报告）
```

实测（bench-real：对治理前告警逐条打开源码人工核验，precision = T/(T+F)）：

| 库 | 治理前 | 治理后 | 真缺陷误杀 |
|---|---|---|---|
| requests | 0.750 | **1.000** | 0 |
| trio | 0.644 | **0.935** | 0 |
| botocore | 0.682 | **0.833** | 0 |
| werkzeug | 0.158 | **0.333** | 0 |

LLM 定级对照实验（三轮，34 条全量）验证了分层边界：向定级 Prompt 注入三条领域
知识后误报击杀率过半，**三轮真缺陷误杀恒为 0**；同时实测 LLM 定级层温度不可复现
（同批条目两轮判定翻转 14.7%）——把不确定的判断压到最窄一层，正是分层的设计理由。
详见 [docs/ai-adjudication-results.md](docs/ai-adjudication-results.md)。

## 真实库基准（bench-real）

不用合成样例自证：对 6 个主流开源库（click / werkzeug / flask / requests /
botocore / trio）治理前的全部告警逐条人工核验，125 条标注含误报模式归因
（A 设计特性当漏洞 / F1 探测惯用法 / RES 资源管理 / NAME 撞名 / G 协议哈希 /
COMMENT 注释误撞等），并固化为 pytest 回归——**任何人改动规则引擎，真缺陷误杀或
precision 回退会立刻测试报红**（已经负向验证：注入过度抑制 → 测试确实能抓到）。

```bash
python -m codeaudit real-eval     # 六库对照报表（免 API）
```

标注与结论：[docs/bench-real-results.md](docs/bench-real-results.md)

## 快速开始

```bash
git clone https://github.com/YUNMENGD/llm-code-audit.git
cd llm-code-audit
pip install -r requirements.txt

# ① 免 API 的静态规则检查（任何人都能直接跑）
python -m codeaudit check examples/vulnerable_app.py

# ② 完整 LLM 审计（先在 .env 配置 API Key，见下）
python -m codeaudit audit examples/vulnerable_app.py -o out/report.md

# ③ 桌面应用（独立窗口，拖拽目录即审）
python desktop.py

# ④ 测试：146 项离线单测 + 六库回归红线
python tests/test_offline.py
python -m pytest tests
```

**团队分发无需装 Python**：`python tools/build_portable.py` 产出
`dist/CodeAudit/CodeAudit.exe` 绿色版（约 104 MB，双击即用，`--selftest` 一键验收）。
`knowledge/`、`prompts/`、`web/` 以可编辑目录随包分发——改规则、调 Prompt 不用重新打包。

### 配置密钥

复制 `.env.example` 为 `.env`，填入大模型 API Key（OpenAI 兼容格式，
通义 / DeepSeek / GLM / Kimi 均可）。**`.env` 已被忽略，严禁提交到仓库；
绿色版分发包内不含任何密钥。**

## 目录结构

```
llm-code-audit/
├── codeaudit/        # Python 包：parser/rules/retriever/audit/validate/report…
├── knowledge/
│   ├── defects/      # 缺陷知识库（JSON，含 CWE 来源标注）
│   └── rules/        # 静态规则库 + 防护特征（guards）
├── prompts/          # 审计 / LLM 定级 Prompt 模板
├── bench-real/       # 6 库人工核验 ground truth（pytest 回归数据源）
├── web/              # 桌面端前端（单页应用，拖拽即审）
├── tools/            # 绿色版打包、LLM 定级实验脚本
├── desktop.py        # 桌面应用入口（pywebview 窗口 + 本地 FastAPI）
├── tests/            # 离线单测 + bench-real 回归红线
├── examples/         # 测试样例代码
├── docs/             # 需求/设计/决策/实验文档
└── out/              # 审计报告与实验产物（不入库）
```

## 项目进度

见 [docs/20天开发计划.md](docs/20天开发计划.md) 与申报书进度安排。
协作规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。
