"""基于大语言模型的代码审计系统（大创项目）。

模块划分（见 docs/interface-design.md）：
- models     共享数据结构
- parser     代码解析与多粒度切分（工程级/文件级/函数级）
- rules      规则库加载与硬性规则校验
- retriever  缺陷知识库检索（RAG，当前为关键词版，D12 换向量版）
- llm        大模型调用封装（OpenAI 兼容）
- audit      审计工作流编排
- validate   结果校验、去重、一致性
- report     审计报告生成
"""

__version__ = "0.1.0"
