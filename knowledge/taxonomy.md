# 缺陷知识库分类树（D8 建，D19 扩容后更新）

> 骨架参考 CWE Top 25 (2024) + OWASP Top 10 (2021) + 常见 Python 陷阱，
> 按本项目四类目重组。knowledge/defects/*.json 的 `id` 前缀与本树一一对应，
> 新增条目先找归属节点，再进文件登记。目标规模：security ≥25、logic ≥15、style ≥10、engineering ≥8。

## 当前进度（D19 扩容后）

| 类目 | 目标 | 实际 | 所在文件 |
|---|---|---|---|
| security | ≥25 | **26** | security_seeds(15) + security_extra(11) |
| logic | ≥15 | **15** | logic_seeds(8) + logic_extra(7) |
| style | ≥10 | **10** | style_seeds(10) |
| engineering | ≥8 | **10** | logic_seeds 内 ENG-001/002 + engineering_seeds(8) |
| 合计 | ≥58 | **61** | 全部带 CWE/PEP/OWASP 来源 |

## S 安全漏洞

| 节点 | ID | 状态 |
|---|---|---|
| 注入类 | CWE-89 SQL / CWE-78 命令 / CWE-95 eval / CWE-94 代码/SSTI / CWE-917 表达式 | ✅ 全有（95/94/917 为 D19 补录） |
| 跨站类 | CWE-79 XSS / CWE-352 CSRF | ✅ |
| 反序列化 | CWE-502 pickle/yaml/marshal | ✅ |
| 路径与文件 | CWE-22 遍历 / CWE-434 上传 / CWE-367 TOCTOU | ✅（367 为 D19 补录） |
| 密码学误用 | CWE-327 弱算法 / CWE-330 弱随机 / CWE-798 硬编码凭据 | ✅（口令存储并入 327 fix） |
| 传输安全 | CWE-295 证书 / CWE-319 明文信道 | ✅（319 为 D19 补录） |
| 访问控制 | CWE-862 缺授权 / CWE-639 对象级越权 / CWE-306 无认证 / CWE-384 会话固定 | ✅（639/306/384 为 D19 补录） |
| 信息泄露 | CWE-200 泄露 / CWE-532 日志泄密 | ✅（532 为 D19 补录） |
| 资源与可用性 | CWE-400 无界输入 / CWE-489 debug 暴露 / CWE-1333 ReDoS | ✅（1333 为 D19 补录） |
| 服务端请求 | CWE-918 SSRF | ✅ |
| 解析器攻击 | CWE-611 XXE | ✅（D19 补录） |

## L 逻辑错误

| 节点 | ID | 状态 |
|---|---|---|
| 边界条件 | LOG-001 空/越界 | ✅ |
| 异常处理 | LOG-002 吞噬/契约混淆 | ✅ |
| 并发 | LOG-003 竞态/无锁共享 | ✅ |
| 资源管理 | LOG-004 泄漏 | ✅ |
| 布尔与条件 | LOG-005 恒真恒假/优先级 | ✅ |
| 数值 | LOG-006 浮点比较 / LOG-013 除零 | ✅（013 为 D19 补录） |
| 别名与共享 | LOG-007 可变默认/浅拷贝 | ✅ |
| 循环 | LOG-008 off-by-one / LOG-015 遍历中修改 | ✅ |
| 返回值契约 | LOG-009 错误被忽略 | ✅（D19） |
| 时间 | LOG-010 时区/DST | ✅（D19） |
| 完备性 | LOG-011 分支/状态覆盖不全 | ✅（D19） |
| 空值 | LOG-012 Optional 未判 | ✅（D19） |
| 递归 | LOG-014 无界递归 | ✅（D19） |

## Y 代码规范（style_seeds.json，D19 新建）

STY-001 命名 / STY-002 docstring / STY-003 导入 / STY-004 魔法数字 /
STY-005 过长函数过深嵌套 / STY-006 死代码 / STY-007 类型标注 /
STY-008 影子变量 / STY-009 结构字符串拼接 / STY-010 日志格式化 — 全部 ✅

## E 工程实践（engineering_seeds.json + logic_seeds 内 2 条）

ENG-001 可观测性 ✅ / ENG-002 依赖版本 ✅ /
ENG-003 环境硬编码 ✅ / ENG-004 供应链锁版本 ✅ / ENG-005 关键路径无测试 ✅ /
ENG-006 异常层错配 ✅ / ENG-007 全局可变状态 ✅ / ENG-008 日志级别 ✅ /
ENG-009 入口副作用 ✅ / ENG-010 凭据扩散 ✅（03-10 为 D19 补录）

## 维护规则

1. 新条目模板字段齐全（id/title/category/severity/tags/triggers/pattern/impact/fix/source）才允许合并。
2. `triggers` 决定检索命中率：每个词必须能在真实代码里字面出现（函数名、API 名、关键字），空想词不要加；
   **禁用 `def `、`for `、`if`、`=`、`f"` 这类全文命中的泛化词**（D19 清理过一批，教训）。
3. 每季度对照 CWE Top 25 榜单变化增补/退役。
4. 与硬性规则的关系：可正则判定的进 rules/，需要语义判断的进 defects/（供 RAG）；两边都有时必须登记进 cwe_map.json。
