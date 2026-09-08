# 第三方静态分析工具基线对比（A 实验）

> 生成：2026-09-08 · 数据 out/tool_baseline.json + out/flood_verdicts.json（本脚本由 tools/tool_baseline_report.py 程序化生成，数字可重放）
> 工具版本：bandit 1.9.4 / semgrep 1.176.1（p/default 规则包）/ pylint 4.0.8（仅启用与 SEC/LOG 同语义的 10 个 code）
> 尺子：bench-real 六库 GT 中 R-SEC-*/R-LOG-* 标注行，±3 行匹配继承人工 verdict；
> ours 同口径。GT 外告警分层抽样 81 条核验（T=0 / F=68 / ?=13；抽样中 22 处逐行实读语境，其余类内同质按规则判定，理由逐条见 out/flood_verdicts.json），按频次加权外推。

## 表1 命中 GT 区：同一批已知缺陷位置上的可信度

| 工具 | 六库总告警 | 命中GT | T | F | ? | precision |
|---|---|---|---|---|---|---|
| bandit | 220 | 23 | 1 | 18 | 4 | **0.053** |
| semgrep | 39 | 9 | 1 | 5 | 3 | **0.167** |
| pylint | 67 | 37 | 1 | 33 | 3 | **0.029** |
| ours | 27 | 27 | 1 | 22 | 4 | **0.043** |

结构性局限（如实声明）：GT 的 SEC/LOG 区内人工判定的真缺陷只有 1 条（werkzeug debug REPL 的 exec），T 覆盖 1/1 四家相同——**本表区分度全在误报侧**；检测能力（recall 维度）由植入缺陷实验（任务 B）另行回答。

## 表2 洪泛区：GT 外告警的加权外推

| 工具 | 洪泛总数 | 外推T | 外推F | 外推? | 未映射规则告警 |
|---|---|---|---|---|---|
| bandit | 197 | 0.0 | 196.0 | 1.0 | 0 |
| semgrep | 30 | 0.0 | 27.0 | 3.0 | 0 |
| pylint | 30 | 0.0 | 21.0 | 9.0 | 0 |

- 三工具洪泛合计 257 条，最大单一来源：B101（143 条，trio 独占 99 条）
- 81 条抽样中真缺陷 0 条；未映射规则的告警 0 条未参与外推（保守：不计入 F 也不计入 T）
- bandit 的 assert 规则（B101）与 semgrep 的 logger-credential-disclosure为最大两类洪泛源；抽样实读中前者全为内部不变量断言（A 模式），后者记录内容为过期时间/角色名等非凭据值（E 模式关键词误判）

## 表3 抽样判定按工具规则归类（81 条全量）

| 工具规则 | 样本 n | 判定 | 模式归类 |
|---|---|---|---|
| B101 | 12 | F | A 设计选择（assert 内部不变量） |
| W0718 | 10 | F | LOG/RERAISE（十处实读无一静默吞） |
| B404 | 7 | F | 提示级 import 存在 |
| B603 | 6 | F | 防护到位（列表参数+shell=False） |
| W1514 | 6 | ? | ? 建议显式 encoding |
| B311 | 5 | F | G 非加密场景随机数（抖动/临时名） |
| B105 | 4 | F | G-ENVNAME（右值是环境变量名非凭据） |
| W1510 | 3 | ? | ? 建议核查返回码 |
| dangerous-globals-use | 3 | F | A 内部符号查表 |
| B104 | 2 | F | E 字符串误撞（host 判断逻辑而非绑定） |
| B324 | 2 | F | G 缓存键哈希 |
| B405 | 2 | F | A 信任域内 XML 解析 |
| B607 | 2 | F | A 打开器功能本体 |
| insecure-hash-algorithm-sha1 | 2 | F | G 缓存键哈希 |
| no-set-ciphers | 2 | ? | ? 部署策略口味 |
| non-literal-import | 2 | F | A 白名单探测/插件注册表 |
| python-logger-credential-disclosure | 2 | F | E 关键词误判（实读无凭据值） |
| B403 | 1 | ? | ? 自有工具 pickle |
| B606 | 1 | F | A 打开器功能本体 |
| B704 | 1 | F | A 内部类型标记 |
| avoid-pickle | 1 | ? | ? 同 B403 |
| detect-insecure-websocket | 1 | F | E docstring 文案误撞 |
| explicit-unescape-with-markup | 1 | F | A 同 B704 |
| httpsconnection-detected | 1 | F | 规则语义倒置（https 用 HTTPSConnection 是对的） |
| python36-compatibility-Popen1 | 1 | F | 提示级（实读下一行 shell=False） |
| tainted-url-host | 1 | F | A TLS 信任域内自拼 https |

## 结论

1. **命中已知缺陷位置**：semgrep 克制（总量最小、命中区 P=0.167），bandit 洪泛最重（197 条 GT 外），pylint 命中最多但几乎全是宽捕获类误报（W0718 十处实读无一真吞异常）。
2. **GT 外告警上抽样未见新真缺陷**（81 条判 T=0）——三家工具的『模式匹配语义』与成熟库的『已知安全写法』存在系统性错位；本项目的 A/F1/G/NAME/COMMENT/LOG/RES 误报模式治理正是对这一错位的工程化回答。
3. ours 命中区 P（0.043）与三方同数量级，但**洪泛为 0**（全部告警落在已核验位置，新增噪声可被回归测试捕获），且可叠加 LLM 定级层（误报击杀>50%、三轮真缺陷零误杀）——分层可控性是三方工具不具备的架构性质。

复现：`python tools/tool_baseline.py`（需 pip install bandit semgrep pylint）→ `python tools/annotate_flood.py` → `python tools/tool_baseline_report.py`
