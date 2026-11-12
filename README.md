# 明查秋毫 —— 基于分层降噪架构的大语言模型代码审计系统（llm-code-audit）

利用大语言模型的语义理解与逻辑推理能力，结合 RAG（检索增强生成）、静态规则引擎、
跨文件调用图与污点追踪、工作流编排，对代码进行**工程级 / 文件级 / 函数级**多粒度审计：
识别安全漏洞、逻辑错误、规范问题，经规则校验与交叉复核后，输出带定位信息和修复建议的
结构化审计报告。支持 **Python + JS/TS** 双语言（静态层 + 语义层）。

**18 条 Python 硬规则 + 12 条 JS/TS 规则 · 61 条缺陷知识 · 6 个真实开源库 125 条人工核验标注 · 零真缺陷误杀红线**

## 分层降噪架构

在成熟开源库上，"报得多"不是能力，噪声才是天花板。本系统以**确定性静态层在前、
概率性 LLM 层在后**的分层设计逐层压缩误报，每一层效果均可量化：

```
代码输入 ──▶ parser（AST 解析/切分）
                │
    ① 静态规则引擎：18 条 Python 硬规则 + 12 条 JS/TS 规则 + 误报模式治理
    │     （字符串遮蔽/探测惯用法/资源管理/方法名撞车/协议哈希/注释误撞/noqa…）
    │     ——零成本、逐字节可复现；大目录进程池并行（结果与串行逐条一致）
    │     + 跨文件调用图（AST fqn 解析）：给 LLM 提供"谁调用了它"的影响范围证据
    │     + 污点追踪（source→sink 目录 + 调用图迭代传播）：数据流证据链注入
    │
    ② RAG 知识检索：61 条缺陷知识（CWE 来源标注）按需注入 Prompt
    │     + Agentic 逃生舱：模型可申请补充检索（NEED-EVIDENCE），系统回填重问
    │
    ③ LLM 分析：函数/文件/工程三级模板（Python）+ 文件级模板（JS/TS）
    │
    ④ validate（行号锚定校验/去重/双模型交叉复核/防护抑制）
    │
    └─▶ report（Markdown / 交互 HTML / 脱敏分享版 / 桌面端报告）
```

实测（bench-real：对治理前告警逐条打开源码人工核验，precision = T/(T+F)）：

| 库 | 治理前 | 治理后 | 真缺陷误杀 |
|---|---|---|---|
| requests | 0.750 | **1.000** | 0 |
| trio | 0.644 | **0.967** | 0 |
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

## 实验矩阵（全部可复现，数据不编造）

| 实验 | 结论 | 文档 |
| --- | --- | --- |
| RAG 消融（关键词 vs 向量融合，119 条 T/F 真值，双查询口径） | 关键词臂 recall@5：文件窗 0.714 / 函数窗 0.592；向量臂待 embeddings 端点（⚠️暂未获取，接口已就绪） | [rag-ablation-results.md](docs/rag-ablation-results.md) |
| 污点追踪真实库量化（六库候选路径逐条人工核验） | precision 0.417（T5/F7），误报模式归因：类型不符/护栏覆盖/常量误染/CLI 自有参数——证据层噪声可控且可解释 | [taint-eval-results.md](docs/taint-eval-results.md) |
| JS/TS 语义审计（bench-js 真实模型调用） | 预埋缺陷 10/10 检出、反例零误报；语义层独有发现 2 条（正则覆盖不到的形态） | [js-audit-results.md](docs/js-audit-results.md) |
| 静态扫描性能（六库串行 vs 进程池） | 结果逐条一致；trio（144 文件）×2.04、botocore ×1.27；小目录并行负优化 → 自动阈值 <64 文件走串行 | [perf-scan-results.md](docs/perf-scan-results.md) |
| LLM 定级对照（三轮 34 条） | 知识注入后误报击杀率过半，三轮真缺陷误杀恒 0；定级层温度不可复现（翻转 14.7%）→ 分层边界依据 | [ai-adjudication-results.md](docs/ai-adjudication-results.md) |

```bash
python tools/rag_ablation.py      # RAG 消融（关键词臂离线；配 EMBEDDING_* 后自动补向量臂）
python tools/taint_eval.py --collect && python tools/taint_eval.py --report
python tools/perf_scan.py         # 性能实测（需 realtest/ 库源码）
python tools/kb_review.py         # 知识库评审门禁：schema 预审 + 零误杀回归
```

## 数据飞轮

- **交互式报告**：桌面端与 `--html` 输出为单文件交互 HTML——按严重度/类别/
  检出方式筛选、文件分组折叠、关键词搜索；数据 JSON 内嵌，浏览器直接打开，零外部依赖。
- **误报反馈回流**：报告里对告警点「标记误报」即入本地队列（`data/feedback/`，
  不入库）；`python tools/promote_feedback.py` 聚合出候选豁免规则——机器只攒证据
  给候选，写入知识库前须经 bench-real 回测人工确认，与"每条豁免可复核"纪律一致。

## 快速开始

```bash
git clone https://github.com/YUNMENGD/llm-code-audit.git
cd llm-code-audit
pip install -r requirements.txt

# ① 免 API 的静态规则检查（任何人都能直接跑）
python -m codeaudit check examples/vulnerable_app.py

# ② 完整 LLM 审计（先在 .env 配置 API Key，见下）
python -m codeaudit audit examples/vulnerable_app.py -o out/report.md

# ②b 增量审计：只审 git 相对 REV 的变更 .py/.js/.ts（调用图等上下文仍全量构建）
python -m codeaudit check . --changed-since HEAD
python -m codeaudit audit . --changed-since HEAD~3

# ②c CI 门禁：存在 ≥medium 问题时退出码 1（GitHub Actions 模板见 examples/codeaudit-gate.yml）
python -m codeaudit audit . --fail-on medium

# ②d 脱敏分享版：路径只留文件名、凭据掩码、可选水印（对外提交/投稿附件用）
python -m codeaudit audit . --share out/share.html --watermark "内部评审"

# ②e 审计报告对比：新增/消除/行号移动/存续（回归验证闭环）
python -m codeaudit diff out/old.json out/new.json

# ②f 大目录并行静态扫描（≥64 文件自动启用；--workers 1 强制串行）
python -m codeaudit check big_project/ --workers 8

# ③ 桌面应用（独立窗口：审计/历史/知识库/规则库/设置/MCP 六页签，深浅主题）
python desktop.py

# ③b MCP 服务器：把审计能力开放给 Claude Desktop / Cursor 等客户端
python -m codeaudit mcp        # 绿色版：CodeAudit.exe --mcp
# 7 工具 + 知识库只读资源 + 审计话术模板；配置在桌面端「MCP」页一键复制

# ④ 测试：251 项离线单测 + 六库回归红线
python tests/test_offline.py
python -m pytest
```

### 桌面端功能一览

| 页签 | 能力 |
| --- | --- |
| 审计 | 静态/AI 双模式（Python+JS/TS）、三粒度、增量审计、双模型交叉复核、few-shot 开关、真实进度条、任务取消、Ctrl+Enter 快捷启动 |
| 历史 | 完成任务自动存档（保留最近 50 次），回看交互报告、删除、导出 HTML/MD/JSON/**脱敏分享版**、勾选两份报告 **diff 对比**（新增/消除/移动/存续） |
| 知识库 | 条目搜索/新增/编辑/删除（自定义写 `knowledge/defects/custom.json`，内置只读保护评测口径）、一键重建向量索引 |
| 规则库 | 硬规则查看 + 自定义正则规则（保存前强制编译校验 + 样例试跑预览），写入即进静态引擎 |
| 设置 | 模型/密钥/端点/温度等在线编辑（密钥脱敏回显、留空不改、只落本地 `.env`）、一键连通性测试 |
| MCP | 7 个标准工具（audit_code 含 JS/TS、list_rules、search_knowledge、list_knowledge、mark_false_positive、audit_history、diff_audits）+ 知识库只读资源 + 审计话术模板，配置一键复制 + 子进程握手自检 |

报告内每条发现支持**一键修复**：修复建议含代码块时生成 diff 预览，证据唯一锚定
（锚不上拒绝应用），确认后写回并自动备份 `.bak-时间戳`。

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
├── codeaudit/        # 引擎包：parser/rules/jsrules/retriever/audit/taint/graph/
│                     #   validate/report/diff/fixer/parallel/history/settings/mcp…
├── knowledge/
│   ├── defects/      # 缺陷知识库（JSON，含 CWE 来源标注；custom.json 在线维护）
│   ├── rules/        # Python 硬规则 + JS/TS 规则 + 防护特征（guards）
│   └── taint/        # 污点 source/sink 目录
├── prompts/          # Python 三级 + JS 文件级审计模板
├── bench-real/       # 6 库人工核验 ground truth（pytest 回归数据源）
├── bench-taint/      # 污点候选路径人工核验标注
├── web/              # 桌面端前端（六页签单页应用）
├── tools/            # 打包、消融/性能/污点实验、评审门禁、反馈聚合
├── desktop.py        # 桌面应用入口（pywebview 窗口 + 本地 FastAPI + --mcp）
├── tests/            # 251 项离线单测 + bench-real 回归红线
├── examples/         # Python/JS 测试样例 + CI 门禁模板
├── docs/             # 需求/设计/决策/实验文档（实验矩阵见上）
└── out/              # 审计报告与实验产物（不入库）
```

## 项目进度

当前路线图见 [docs/roadmap-v2.md](docs/roadmap-v2.md)（v2 设置中心/知识库/MCP/历史、
v3 污点/消融/diff/JS 试点/一键修复/评审门禁、v4 污点量化/并行/分享版/JS 语义层均已落地）；
历史阶段归档见 [docs/20天开发计划.md](docs/20天开发计划.md)。
协作规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。
