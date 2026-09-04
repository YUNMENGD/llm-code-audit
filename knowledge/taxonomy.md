# 缺陷知识库分类树（D8）

> 骨架参考 CWE Top 25 (2024) + OWASP Top 10 (2021) + 常见 Python 陷阱，
> 按本项目四类目重组。knowledge/defects/*.json 的 `id` 前缀与本树一一对应，
> 新增条目先找归属节点，再进文件登记。目标规模：security ≥25、logic ≥15、style ≥10、engineering ≥8。

## S 安全漏洞（security_seeds.json，现有 15）

| 节点 | ID | 状态 |
|---|---|---|
| 注入类 | CWE-89 SQL / CWE-78 命令 / CWE-95 eval / CWE-77 参数 | ✅ 已有 |
| 跨站类 | CWE-79 XSS / CWE-352 CSRF | ✅ 已有，SSTI 模板注入 ⬜ |
| 反序列化 | CWE-502 pickle/yaml/marshal | ✅ |
| 路径与文件 | CWE-22 遍历 / CWE-434 上传 | ✅ |
| 密码学误用 | CWE-327 弱算法 / CWE-330 弱随机 / CWE-321 硬编码密钥 | ✅（口令存储专项 ⬜） |
| 传输安全 | CWE-295 证书 / CWE-319 明文信道 | ✅（TLS 版本降级 ⬜） |
| 访问控制 | CWE-862 缺授权 / CWE-639 对象级越权 | ✅（认证缺失/会话固定 ⬜） |
| 信息泄露 | CWE-200 泄露 / CWE-532 日志泄密 | ✅ |
| 资源与可用性 | CWE-400 无界输入 / CWE-489 debug 暴露 | ✅（正则 ReDoS ⬜） |
| 服务端请求 | CWE-918 SSRF | ✅ |
| 待补高频 | CWE-611 XXE ⬜ / CWE-917 表达式注入 ⬜ / CWE-367 TOCTOU ⬜ |

## L 逻辑错误（logic_seeds.json，现有 8）

| 节点 | ID | 状态 |
|---|---|---|
| 边界条件 | LOG-001 空/越界 | ✅ |
| 异常处理 | LOG-002 吞噬/契约混淆 | ✅ |
| 并发 | LOG-003 竞态/无锁共享 | ✅ |
| 资源管理 | LOG-004 泄漏 | ✅ |
| 布尔与条件 | LOG-005 恒真恒假/优先级 | ✅ |
| 数值 | LOG-006 浮点比较 | ✅ |
| 别名与共享 | LOG-007 可变默认/浅拷贝 | ✅ |
| 循环 | LOG-008 off-by-one/遍历中修改 | ✅ |
| 待补 | LOG-009 业务语义偏差（返回值被忽略）⬜ / LOG-010 时区与时间处理 ⬜ / LOG-011 状态机漏态 ⬜ / LOG-012 类型混淆（Optional 未判）⬜ |

## Y 代码规范（style，待建 style_seeds.json）

命名（PEP8）/ 导入组织 / 注释与 docstring / 行宽与格式 / 死代码 /
魔法数字 / 类型标注缺失 / 影子变量 / 过度嵌套（圈复杂度）/ 重复代码块

## E 工程实践（engineering，部分已并入 logic_seeds）

ENG-001 可观测性 ✅ / ENG-002 依赖锁定 ✅ /
待补：ENG-003 配置写死 ⬜ / ENG-004 环境漂移（requirements 无上限版本）⬜ /
ENG-005 无测试的关键路径 ⬜ / ENG-006 错误吞在边界（跨模块契约）⬜ /
ENG-007 单例全局状态滥用 ⬜ / ENG-008 日志级别错用 ⬜

## 维护规则

1. 新条目模板字段齐全（id/title/category/severity/tags/triggers/pattern/impact/fix/source）才允许合并。
2. `triggers` 决定检索命中率：每个词必须能在真实代码里字面出现（函数名、API 名、关键字），空想词不要加。
3. 每季度对照 CWE Top 25 榜单变化增补/退役。
4. 与硬性规则的关系：可正则判定的进 rules/，需要语义判断的进 defects/（供 RAG）；两边都有时必须登记进 cwe_map.json。
