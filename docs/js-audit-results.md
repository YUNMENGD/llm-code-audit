# JS/TS 语义层审计验证（bench-js · 真实模型调用）

- 日期：2026-11-12 · 模型：deepseek-chat · 粒度：文件级（JS 试点口径）
- 对象：examples/bench-js（3 个正例文件预埋 10 处缺陷 + 1 个反例文件全安全写法）
- 链路：jsrules 静态线索 → js_file_audit.md 模板 → LLM 语义审计 → 证据校验 → 合并去重

## 结果

| 指标 | 数值 | 说明 |
| --- | --- | --- |
| 预埋缺陷检出 | **10/10** | 全部命中，其中 9 条「规则+LLM」双源共识 |
| 反例误报 | **0** | neg01_safe.js（参数化/净化/抑制标记/注释）零告警 |
| 语义层独有发现 | 2 条 | JS-SEC-005 命令注入（静态正则未覆盖该形态，LLM 补上）；DISCOVERED-JS-LOG-009-01 exec 错误未处理（中危） |
| 模型调用 | 4 次 | 每文件 1 次，缓存未命中口径 |

## 明细（12 条告警）

| 位置 | 规则 | 检出方式 | 问题 |
| --- | --- | --- | --- |
| pos01_eval.js:2 | JS-SEC-001 | 规则+LLM | location.hash 输入直达 eval |
| pos01_eval.js:4 | JS-SEC-002 | 规则+LLM | new Function 动态构造 |
| pos01_eval.js:5 | JS-SEC-006 | 规则+LLM | SQL 模板串拼接 |
| pos02_xss.js:7 | JS-SEC-005 | LLM | child_process.exec 命令注入 |
| pos02_xss.js:3 | JS-SEC-003 | 规则+LLM | innerHTML XSS |
| pos02_xss.js:4 | JS-SEC-004 | 规则+LLM | document.write XSS |
| pos03_misc.ts:2 | JS-SEC-007 | 规则+LLM | Math.random 生成令牌 |
| pos03_misc.ts:3 | JS-SEC-008 | 规则+LLM | 关闭 TLS 校验 |
| pos03_misc.ts:4 | JS-SEC-009 | 规则+LLM | 硬编码 API 密钥 |
| pos02_xss.js:7 | DISCOVERED-JS-LOG-009-01 | LLM | exec 错误未处理（中危） |
| pos03_misc.ts:5 | JS-LOG-001 | 规则+LLM | 空 catch 吞异常 |
| pos03_misc.ts:8 | JS-ENG-001 | 规则+LLM | debugger 滞留 |

## 结论

分层降噪架构在第二语言上原样运转：静态层给线索与双源背书，语义层补正则
覆盖不到的形态（回调契约、模板串命令注入），反例零误报说明豁免纪律
（eslint-disable / 注释遮蔽 / 安全写法白名单）跨语言有效。

> 口径说明：bench-js 为小样本试点基准（10 处预埋），不是大规模评测；
> 结论限定为「架构可迁移性验证」，不外推为 JS 生态的整体 precision。
> 复现：`python -m codeaudit audit examples/bench-js`（需配置模型密钥）。
