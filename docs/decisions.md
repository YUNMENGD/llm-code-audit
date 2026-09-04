# 技术选型决策记录（D1 讨论稿）

> 状态：待 9/5 启动会确认。每项含背景 / 决定 / 影响。确认后把状态改为「已定」。

## ADR-001 审计语言范围
- 背景：多语言支持成本高，申报书要求覆盖安全漏洞+逻辑+规范。
- 决定（建议）：**第一阶段只做 Python**，Java/C++ 预留 parser 接口。
- 影响：tree-sitter 可后置，先用内置 ast 模块即可开工。

## ADR-002 大模型接口
- 背景：需要低门槛、额度可控、支持 embedding 同一体系。
- 决定（建议）：主力 **通义千问（DashScope OpenAI 兼容模式）**，备用 DeepSeek；
  统一走 OpenAI 兼容协议封装，切模型只改 `.env`。
- 影响：`llm.py` 只需一套 HTTP 逻辑；交叉复核可用双模型。

## ADR-003 工作流框架
- 背景：申报书要求 Workflow 或 ReAct Agent。
- 决定（建议）：**先用自研轻量编排**（parser→retriever→audit→validate→report 线性流），
  LangGraph 作为第二阶段备选，避免框架学习成本吃掉开发时间。
- 影响：代码全自写、答辩可控性强。

## ADR-004 向量检索
- 背景：RAG 需要 embedding + 向量库。
- 决定（建议）：**chromadb（本地）+ DashScope text-embedding-v3**。
- 影响：D12 前用关键词检索占位（已实现），接口签名保持一致，届时只换实现。

## ADR-005 仓库形态
- 背景：大创项目未发表。
- 决定：**GitHub 私有仓库** `YUNMENGD/llm-code-audit`，main 保护 + PR 制度。

## ADR-006 交付接口
- 背景：结题需要可演示系统。
- 决定（建议）：CLI 优先（已实现），FastAPI Web 界面放 11 月后按需追加。
