# 基于大语言模型的代码审计系统（llm-code-audit）

> 西安工业大学 国家级大学生创新训练计划项目
> 项目负责人：杨梦颢 ｜ 指导教师：喻钧

利用大语言模型的语义理解与逻辑推理能力，结合 RAG（检索增强生成）与工作流编排，
对代码进行**工程级 / 文件级 / 函数级**多粒度审计：识别安全漏洞、逻辑错误、规范问题，
经规则校验与交叉复核后，输出带定位信息和修复建议的结构化审计报告。

## 架构总览

```
代码输入 ──▶ parser（AST 解析/切分） ──▶ retriever（知识库检索 RAG）
                                                │
                    prompts（Prompt 模板） ──▶ audit（LLM 分析）
                                                │
                    validate（规则校验/去重/一致性） ──▶ report（Markdown/HTML 报告）
```

| 模块 | 路径 | 职责 | 分工 |
|---|---|---|---|
| 代码处理 | `codeaudit/parser.py` | AST 解析、函数/文件级切分、行号映射 | 成员认领 |
| 知识库 | `knowledge/` + `codeaudit/retriever.py` | 缺陷知识库、规则库、检索 | 成员认领 |
| 模型分析 | `codeaudit/audit.py` + `llm.py` + `prompts/` | 工作流编排、Prompt、LLM 调用 | 成员认领 |
| 结果验证 | `codeaudit/validate.py` | 规则二次校验、去重、一致性 | 负责人 |
| 报告生成 | `codeaudit/report.py` | 结构化审计报告 | 成员认领 |

## 快速开始

```bash
git clone https://github.com/YUNMENGD/llm-code-audit.git
cd llm-code-audit
python -m venv .venv
.venv\Scripts\activate        # Windows；macOS/Linux 用 source .venv/bin/activate
pip install -r requirements.txt

# 免 API 的静态规则检查（任何人都能直接跑）
python -m codeaudit check examples/vulnerable_app.py

# 完整 LLM 审计（需先在 .env 配置 API Key，见下）
python -m codeaudit audit examples/vulnerable_app.py -o out/report.md

# 运行离线测试
python tests/test_offline.py

# 桌面应用形态（独立窗口，拖路径即审）
python desktop.py
```

### 桌面应用（F 项）

`python desktop.py` 启动独立窗口：静态检查模式全程免费，AI 深度审计读取 `.env` 配置。
pywebview 装不上时自动退化为浏览器模式（同一服务、功能一致）。仅监听 127.0.0.1，不对外网开放。

### 配置密钥

复制 `.env.example` 为 `.env`，填入大模型 API Key。**`.env` 已被忽略，严禁提交到仓库。**

## 目录结构

```
llm-code-audit/
├── codeaudit/        # Python 包：五大模块
├── knowledge/
│   ├── defects/      # 缺陷知识库（JSON，含 CWE 来源标注）
│   └── rules/        # 代码规则库（硬性规则可程序校验）
├── prompts/          # Prompt 模板（函数级/文件级/工程级）
├── examples/         # 测试样例代码
├── tests/            # 离线单元测试
├── docs/             # 需求/设计/决策/计划文档
└── out/              # 审计报告输出（不入库）
```

## 项目进度

见 [docs/20天开发计划.md](docs/20天开发计划.md) 与申报书进度安排。
协作规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。
