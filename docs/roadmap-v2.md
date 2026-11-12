# 路线图 v2（2026-11 起）

> 取代《20天开发计划》作为当前路线图；旧计划保留作历史归档。
> 原则不变：分层降噪、零真缺陷误杀红线、每条豁免可复核、评测口径稳定。

## 已落地（本轮）

### P0 · 稳定性修复
- [x] 任务表内存上限（30）+ 最旧已结束任务自动淘汰；单任务进度日志上限 2000 行
- [x] 静态扫描单文件读取失败容错跳过（计入 engine.skipped），不再整任务崩溃
- [x] 并发提交任务显示排队状态（进度日志串行执行的提示可见）
- [x] 增量审计无变更时明确提示"无需扫描"
- [x] 系统文件对话框独立线程 + 120s 超时回退手输，不再可能挂死请求

### P1 · 配置与开放能力
- [x] **设置中心**（`codeaudit/settings.py` + `/api/settings`）：模型/密钥/端点/
      温度/重试/一致性轮数/交叉复核默认值在线编辑；密钥脱敏回显、留空=保持不变、
      只写本地 `.env`（原子替换）；一键连通性测试
- [x] **知识库配置**（`codeaudit/kbadmin.py` + `/api/kb`）：条目搜索/增删改，
      自定义写 `knowledge/defects/custom.json`，内置条目只读（评测口径保护）；
      一键重建向量索引（清 `data/vec` 派生物 + 内存缓存）
- [x] **规则库管理**（`/api/rules`）：自定义正则规则增删改，保存前强制编译校验，
      样例试跑预览命中行；写入即进静态引擎
- [x] **MCP 服务器**（`codeaudit/mcpserver.py`，零第三方依赖 stdio JSON-RPC）：
      6 工具 audit_code / list_rules / search_knowledge / list_knowledge /
      mark_false_positive / audit_history；`python -m codeaudit mcp` 或
      `CodeAudit.exe --mcp` 启动；桌面端一键复制客户端配置 + 子进程握手自检

### P2 · 体验升级
- [x] **审计历史**（`codeaudit/history.py` + `/api/history`）：完成自动存档，
      保留最近 50 次，回看交互报告 / 删除 / 导出
- [x] **报告导出**：HTML / Markdown / JSON 一键下载（当前结果与历史均可）
- [x] **任务取消**（`/api/cancel`）：排队即停；静态在文件间隙停；AI 在当前调用返回后停
- [x] **前端重构**：六页签导航、深/浅主题（localStorage 记忆）、真实进度条、
      统计卡片、toast、Ctrl+Enter、全部用户内容 XSS 转义
- [x] 交叉复核 / few-shot 开关进审计界面

### 质量
- [x] 离线测试 168 → 203 项（新增 settings / kbadmin / history / MCP 四组）
- [x] pytest 30 项回归全绿

## 已落地（v3 轮：论文导向七项）

- [x] **RAG 消融实验**（tools/rag_ablation.py + docs/rag-ablation-results.md）：
      以 bench-real 119 条 T/F 标注为真值，双查询口径（文件窗/函数窗）测
      recall@5；关键词臂已出数（文件窗 0.714 / 函数窗 0.592），向量臂待
      embeddings 端点（如实标注⚠️暂未获取）。附带修复两个真实缺陷：
      cwe_map 五条映射指向不存在条目（已修正到真实条目）；STY-006 缺
      TODO/FIXME 触发词（已补，六库零误杀回归通过）
- [x] **跨文件污点追踪**（codeaudit/taint.py + knowledge/taint/catalog.json）：
      source→sink 目录 + 调用图迭代传播（≤6 轮不动点），候选路径带行号
      注入审计 Prompt；AUDIT_TAINT=0 可关；失败自动降级
- [x] **审计对比 diff**（codeaudit/diff.py + CLI diff 子命令 + /api/history-diff
      + 历史页勾选对比 UI）：新增/消除/行号移动/存续四态，drift 容忍
- [x] **JS/TS 多语言试点**（codeaudit/jsrules.py + knowledge/rules/js_rules.json
      12 条 + examples/bench-js 正反例）：check/桌面静态审计按后缀分流；
      注释遮蔽 + eslint-disable 抑制；Python 路径零影响（规则加载器隔离）
- [x] **一键修复**（codeaudit/fixer.py + /api/fix/preview|apply + 报告页按钮）：
      围栏代码块提取 + 证据唯一锚定（锚不上拒绝）+ .bak 时间戳备份
- [x] **MCP resources/prompts**：知识条目只读资源（index + 逐条 URI）、
      audit_file / review_false_positive 两个提示模板；真实子进程验证通过
- [x] **知识库评审门禁**（tools/kb_review.py + examples/kb-review-gate.yml）：
      schema/来源/正则/ID 冲突机器预审 + bench-real 零误杀红线回归
- [x] 离线测试 203 → 234 项；pytest 30 项；v3 端到端冒烟 14 项全过

## 已落地（v4 轮：实验数据与工程深化）

- [x] **污点追踪真实库量化**（tools/taint_eval.py + bench-taint/annotations.json
      + docs/taint-eval-results.md）：六库 12 条候选逐条人工核验，
      precision 0.417（T5/F7），误报模式归因（类型不符/护栏覆盖/常量误染/
      CLI 自有参数）；顺带修复嵌套函数重复统计口径
- [x] **静态扫描并行化**（codeaudit/parallel.py + check --workers +
      tools/perf_scan.py + docs/perf-scan-results.md）：进程池按文件分片，
      结果与串行逐条一致；实测 trio ×2.04 / botocore ×1.27，小目录负优化
      → 自动阈值 <64 文件串行；冻结态回退串行
- [x] **脱敏分享版**（render_share_html + audit --share/--watermark +
      /api/share + 前端分享按钮）：路径只留文件名、凭据掩码、斜向水印，
      对外提交/投稿附件可用
- [x] **JS/TS 语义层审计**（prompts/js_file_audit.md + audit 语言分流 +
      gitdiff 扩展后缀 + docs/js-audit-results.md）：bench-js 真实模型调用
      预埋缺陷 10/10、反例零误报、语义层独有发现 2 条
- [x] **MCP 第七工具 diff_audits** + audit_code 静态分支纳入 JS/TS
- [x] pytest.ini 收集配置（独立脚本式离线测试不再被 pytest 误收集）
- [x] 离线测试 234 → 251 项；pytest 30 项；六库零误杀；v4 冒烟 12/12
- [x] README 全面更新（实验矩阵/双语言/新命令/去实名）

## 已落地（v5 轮：精度治理与弹药扩充）

- [x] **污点精度治理**（四条通用规则，非针对个案）：①open/eval/exec 只认
      裸内置调用（末段名判定）②send_file(BytesIO/StringIO) 内存对象过滤
      ③字符串遮蔽后判外部特征 + __file__ 常量不染色 ④parse_args 派生
      CLI 信任色传播与过滤（AUDIT_TAINT_CLI=1 可保留）。
      同一标注基线重测：候选 12→5，precision **0.417→1.0**，
      真流 5/5 零丢失，被滤 7 条全部为此前核验的 F；过滤计数透明入 stats
- [x] **JS/TS 知识弹药**（knowledge/defects/js_seeds.json 六条，CWE 来源）：
      DOM XSS / 动态执行 / 命令注入 / SQL 注入 / 不安全随机数 / 原型链污染；
      知识库 61→67 条，JS 查询检索命中验证通过
- [x] 离线测试 251 → 259 项；pytest 30 项；六库零误杀；评审门禁 PASS
- [x] 绿色版 v5 重打包：frozen selftest PASS（规则18/知识67/静态+AI 双模式），
      exe --mcp 七工具+资源+模板握手 PASS；包内密钥与测试残留已清理

## 待办（按价值排序，未承诺时间）

1. **向量臂补数**：拿到有效 embeddings 端点后在设置页填 EMBEDDING_*，
   重跑 tools/rag_ablation.py 即得两臂对照表（框架已就绪）
2. **JS/TS 深化**：tree-sitter AST 级精度、函数级切分、JS 基准扩样
3. **污点治理外推验证**：在六库之外的新仓库上盲测治理后 precision，
   检验规则泛化性（当前 1.0 是小样本治理效果，不外推）
4. **进度条精确化**：并行扫描按完成文件数推进（当前按日志行解析）

## 红线（任何新功能不得触碰）

- 内置知识库/规则只读，评测口径（bench-real 125 标注）不因界面操作漂移
- 密钥永不入库、永不回显明文、永不上传外部服务
- 误报反馈只攒候选证据，写知识库前必须人工确认 + bench-real 回测
- 零真缺陷误杀：任何抑制/豁免逻辑必须可解释、可复核
