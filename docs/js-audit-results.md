# JS/TS 函数级语义审计验证（bench-js 扩样 · 真实模型调用）

- 日期：2026-11-12 · 模型：deepseek-chat · 粒度：**函数级**（v6 新增轻量函数切分）
- 对象：examples/bench-js 扩样至 7 文件（5 正例预埋 13 处缺陷 + 2 反例全安全写法）
- 链路：jsparser 函数切分（brace 状态机，零依赖）→ jsrules 静态线索 → js_file_audit 模板 → LLM 语义审计 → 证据校验 → 合并去重

## 结果

| 指标 | 数值 | 说明 |
| --- | --- | --- |
| 预埋缺陷检出 | **13/13** | 含原型链污染、不安全反序列化、开放重定向等扩样缺陷 |
| 反例误报 | **0** | neg01/neg02（参数化/白名单/危险键过滤/安全 schema/抑制标记）零告警 |
| 语义层独有发现 | 3 条 | CWE-502 不安全反序列化、CWE-1321 原型链污染、STY-003 通配导入（静态正则未覆盖） |
| 函数切分 | 4 函数命中 | safeMerge/renderComment/mergeConfig/loadProfile 正确切出；顶层语句文件回退文件级 |
| 模型调用 | 7 次 | 每单元 1 次 |

## 函数级 vs 文件级

v5 文件级审计已能检出多数缺陷；v6 函数级的增量价值：
- **定位更精**：告警绑定到具体函数（mergeConfig/loadProfile），而非整文件；
- **上下文更聚焦**：单函数源码进 Prompt，模型对函数内数据流判断更稳；
- **切分鲁棒**：顶层语句/无函数文件自动回退文件级，不丢审计覆盖。

## 明细（16 条告警，节选语义层独有发现）

| 位置 | 规则 | 检出方式 | 问题 |
| --- | --- | --- | --- |
| pos05_deser.ts:4 | CWE-502 | LLM | js-yaml 非安全加载，可构造任意对象 RCE |
| pos04_proto.js:3 | DISCOVERED-CWE-1321-01 | LLM | mergeConfig 未过滤 __proto__，原型链污染 |
| pos05_deser.ts:2 | STY-003 | LLM | 通配导入污染命名空间 |
| pos04_proto.js:11 | （开放重定向） | LLM | req.query.url 直达 res.redirect |

其余 12 条为「规则+LLM」双源共识或静态规则命中（eval/new Function/SQL 拼接/
innerHTML/document.write/Math.random/TLS 关闭/硬编码密钥/空 catch/debugger）。

## 结论与诚实口径

分层降噪架构在第二语言上以**函数级粒度**原样运转：静态层给线索与双源背书，
语义层补正则覆盖不到的形态（反序列化/原型链/回调契约），反例零误报说明豁免
纪律跨语言、跨粒度有效。

> 口径说明：bench-js 为小样本试点基准（13 处预埋），结论限定为「架构可迁移性
> + 函数级切分可行性验证」，不外推为 JS 生态整体 precision。函数切分为 brace
> 状态机近似（非完整 AST），极端嵌套/装饰器可能切偏，切偏时回退文件级。
> 复现：`python -m codeaudit audit examples/bench-js -d function`（需配置模型密钥）。
