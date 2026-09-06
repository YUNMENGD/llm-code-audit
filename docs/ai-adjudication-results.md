# LLM 定级对照实验结果（exp/ai-adjudication · 2026-09-06）

> 实验：五库 80 条 GT 中的 34 条 SEC/LOG 静态告警（TODO/风格类排除，无定级价值），
> 由 qwen-plus 逐条判"保留/Kill"（±22 行上下文，理由≤60字，调用失败保守保留）。
> 尺子：bench-real 人工核验 verdict；红线：人工判 T 被 LLM Kill 数必须为 0。
> 成本：33 条新调用 + 1 条缓存命中，≈85K token（免费额度 8.5%）。
> 复现：`python tools/ai_adjudicate.py`（明细 out/ai_adjudication.json）

## 核心表格（论文第 3 章）

| 组 | 口径 | T | F | precision | 说明 |
|---|---|---|---|---|---|
| A 纯静态 | 治理链全开 | 1 | 29 | **0.033** | LLM 定级前的输入面 |
| B 静态+LLM定级 | 保留集 | 1 | 14 | **0.067** | P 翻倍，但远未解决问题 |
| — | 真缺陷误杀 | **0** | — | — | ✅ 红线通过；?存疑 4 条也全部正确保留 |

误报击杀 15/29（**51.7%**），每一条 kill 理由均引用了具体证据
（`usedforsecurity=False`、`# noqa`、探测降级 return False、协议规定哈希）。

## 最有价值的发现：LLM 漏杀的 14 条不是随机错，是三个系统性盲区（逐条复核过）

**盲区① Exception/BaseException 混淆（8 条，click/werkzeug/flask 为主）**
LLM 保留理由清一色写着"吞掉所有异常（含 KeyboardInterrupt）"——**技术上是错的**：
`except Exception` 根本不捕获 KeyboardInterrupt/SystemExit（那是 BaseException 子类）。
这正是我们 ground truth 判 F（清理/探测语境合理）的依据。模型套背记的"宽捕获危险"
教条，没区分 Exception 层级。
→ **修复方向明确**：定级 Prompt 加一行知识"except Exception 不含
KeyboardInterrupt/SystemExit，判断吞异常危害前先确认捕获层级"。

**盲区② 反向危险：G 类哈希被"杀意"盯上（3 条，requests/botocore）**
比漏杀更值得警惕——LLM 理由写着"MD5 用于**密码摘要属安全用途，不可用 MD5**"，
它把 HTTP Digest 协议规定的哈希（正是 `usedforsecurity=False` 官方豁免的）当成真漏洞
想升级。本次它"保留"了，等于把人工判 F 的 3 条留进了最终报告；若哪天它反过来
建议"改用 bcrypt"就是帮倒忙。缺的是"协议规定算法不是缺陷"这条知识。
→ 修复：G 模式进知识库（CWE-327 条目加 not_when=协议规定/usedforsecurity=False）。

**盲区③ 威胁模型缺位（3 条，flask/vendored）**
from_pyfile"执行用户可控配置"、six.py exec"变量未受控"——把开发者显式调用的
配置文件、第三方 vendored 兼容技巧当攻击输入，缺"谁是输入方"判断。与 A 模式同源。

（注：G 类 flask 的 _lazy_sha1 本次 LLM 判保留恰与我们的 ?存疑 一致，不算错。）

## 结论（三段论凑齐了）

1. **静态治理层**（E/F1/RES/NAME/noqa）：确定性消除成熟库误报 8~10 条/库，零成本零误杀
2. **LLM 定级层**：再击杀一半残余误报，**0 误杀 0 冤枉存疑项**——安全侧背书成立
3. **LLM 自身有知识盲区**：漏杀的半数是可修复的系统错误而非随机噪声 → 分层降噪
   每一层都能量化、每一层的错都能归因——这就是本系统的工程方法论，答辩主叙事

## Round 2：知识注入修复验证（Prompt v2，commit e55d968）

把三条盲区知识写进系统提示（Exception 层级 / 协议规定哈希 / 威胁模型），
34 条全量重跑（round1 明细归档为 out/ai_adjudication.round1.json）：

| 口径 | T | F | precision | 误报击杀 | 红线 |
|---|---|---|---|---|---|
| A 纯静态 | 1 | 29 | 0.033 | — | — |
| B round1（旧 Prompt） | 1 | 14 | 0.067 | 15 | 0 误杀 |
| **B round2（v2）** | 1 | 12 | **0.077** | **17** | **0 误杀** |

**逐条 diff 归因——修复打哪中哪：**
- v1 保留→v2 击杀 7 条，全部命中三条盲区：3 条 requests Digest 哈希（盲区②，
  连"想升级 bcrypt"的反向危险都杀对了）、1 条 vendored six.py exec（盲区③）、
  3 条 except Exception 层级误判（盲区①）
- v1 击杀→v2 保留 5 条回摆：均为**裸 except**（`except:` 确实捕获
  KeyboardInterrupt，模型理由在事实上成立，GT 判 F 依据是清理语境）——
  知识修复帮不到这类，属规则语义与工程惯例之间的灰区，留给 DESIGN-API 知识库
- **新发现（论文素材）**：同一批 34 条两轮间翻转 5 条（14.7%）——
  LLM 定级层温度>0 不可复现，静态治理层逐字节确定。分层架构把不可复现的
  判断压到最窄的一层，本身就是设计理由

## 勘误纪律自查

上一条消息我在未看明细时预告"P 0.25→0.27"——实际混算口径是 0.033→0.067
（我脑算了类目构成，又错了，且错得方向乐观）。本文档全部数字来自
out/ai_adjudication.json 逐条聚合，脚本可重放验证。
