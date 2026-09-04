# 存储与配置设计（D6）

> 版本 v0.9 ｜ 9/9 评审 ｜ 与 interface-design.md §9 配套

## 1. 配置体系（单一来源：环境变量）

所有配置走 `.env`（python-dotenv 加载），代码内零硬编码配置。

| 键 | 默认 | 说明 |
|---|---|---|
| LLM_API_KEY | 空=降级静态 | 主模型密钥 |
| LLM_BASE_URL | DashScope 兼容端点 | OpenAI 协议，换供应商只改此项 |
| LLM_MODEL | qwen-plus | 主审模型 |
| LLM_FALLBACK_MODEL / _API_KEY | 空 | 交叉复核第二模型（D15） |
| EMBEDDING_MODEL | text-embedding-v3 | D12 向量检索启用 |
| AUDIT_TEMPERATURE | 0.1 | 固定低温保一致性（NFR-1） |
| AUDIT_MAX_RETRY | 3 | LLM 调用重试上限 |
| AUDIT_CONSISTENCY_RUNS | 1 | ≥2 时自动跑一致性比对 |
| AUDIT_CONF_DROP | 0.5 | 置信度丢弃阈值 |
| AUDIT_CONF_REVIEW | 0.7 | 待人工确认阈值 |

规则：**新增配置必须同时改 `.env.example` + 本表 + 用到它的模块文档段落**，三处一致才算完成。
密钥红线：`.env`/key 文件在 .gitignore；CI 与本地都不打印密钥值；示例代码一律用 `sk-your-key-here`。

## 2. 数据文件布局（入库的 = 资产，不入库的 = 产物）

```
llm-code-audit/
├── knowledge/            # 【入库】审计资产，PR 评审制变更
│   ├── defects/*.json    #   缺陷知识库（种子40条，目标≥50）
│   ├── rules/*.json      #   硬性规则 + cwe_map 映射表
│   └── taxonomy.md       #   缺陷分类树（D8 产出）
├── prompts/*.md          # 【入库】Prompt 模板，版本随 git 历史走
├── examples/*.py         # 【入库】标注样例集（验收基准）
├── tests/                # 【入库】离线测试
├── out/                  # 【不入库】报告产物 report.md/json
├── data/                 # 【不入库】向量索引、审计缓存
│   └── cache/audit_cache.json  # 增量缓存：sha256(src+prompt_ver+model) → issues
└── .env                  # 【不入库】密钥
```

## 3. 知识库存储格式决策

- **JSON 文件而非 SQLite/向量库**：人是第一读者，git diff 可读可评审，结题材料直接引用；向量索引是派生物（data/ 可由 knowledge/ 全量重建，删了不心疼）。
- 文件按类目拆分（security/logic/...），单文件 <500 行，冲突面小。
- 每条必带 `source`；无来源的条目 PR 不予合并（红线）。

## 4. 审计缓存设计（FR-7，D17 实现）

```
key   = sha256(源码字节 + prompt文件名+内容hash + 模型名)
value = {issues:[...], ts, tokens_used}
位置  = data/cache/audit_cache.json（本地，不入库）
失效  = prompt 或模型变更自动 miss；--no-cache 强制重审
```

## 5. 用量监控

llm.py 每次调用后向 `out/usage.log` 追加一行（时间、模型、prompt/completion token、耗时）。
免费额度 100万/模型：按试跑均值（8单元≈2.4万token），**每模型约可审 300+ 个函数单元**；
控制台开启「用完即停」，用量页设 80% 预警提醒负责人。

## 6. 环境与依赖策略

- Python ≥3.10（开发用 3.12）；requirements.txt 只放必需项，重型依赖（chromadb/tree-sitter）到对应里程碑再解注释，降低新成员上手门槛。
- 每人流程：clone → venv → pip install → 拷 .env.example 为 .env 填自己的 key → `python -m codeaudit selfcheck` → `python tests/test_offline.py` 全绿即环境就绪。
