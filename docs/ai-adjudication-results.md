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

## Round 3：盲区下沉静态层（T2，commit 19037c2）

把 round2 归因的三个盲区中**可确定性识别**的信号从 LLM 层下沉到规则引擎：
- `logged_check`：except 块体含 logger/warnings/traceback/showtraceback 即"捕获+上报+降级"，非吞掉（botocore endpoint/history、werkzeug console 实证）
- `exclude: usedforsecurity=False`：官方非安全用途声明同行豁免（requests 3 条 + botocore compat，源码该行就带着声明，零成本）
- `skip_path_rx`：`_vendor|vendored|site-packages` 路径下 R-SEC-003 整条停用（vendored six.py，威胁模型非本仓库攻击面）

**bench-real 五库回测（80 条，误杀仍为 0）：**
requests 0.75→**1.0** | botocore 0.682→**0.833** | werkzeug 0.158→**0.333** | click 持平 | flask 持平

**LLM 定级队列 34→26，三轮端到端漏斗（分母统一只算 T+F）：**

| 阶段 | 队列 | T | F | precision | 误杀 | 成本 |
|---|---|---|---|---|---|---|
| A 治理前纯静态 | 34 | 1 | 29 | 0.033 | — | 免费 |
| A' 治理后纯静态 | 26 | 1 | 21 | **0.045** | 0 | 免费 |
| B round2 混合 | — | 1 | 12 | 0.077 | 0 | LLM |
| B round3 混合 | 26 | 1 | 16 | **0.059** | 0 | LLM |

**诚实的反转**：round3 混合精度（0.059）反而**低于** round2（0.077）。逐条归因——
静态下沉确实把 3 条 LLM 误保留的 F 拿掉了，但改 R-LOG-001 的 why 文本导致缓存键
变更、7 条 pass 型 except 重掷，其中 7 条从击杀翻回保留。净效应 −3+7 = +4 F。
根因不是静态层变差（A' 明明升到 0.045），是 **LLM 层的温度不确定性**被 Prompt 文案改动触发重掷。
→ 论文价值：静态层无此敏感（A→A' 单调改善可复现），不确定性完全集中在 LLM 定级层，
分层把不可复现判断压到最窄一层这一设计动机，被 round3 反向印证了一次。

**深层发现（比数字更有价值）**：round3 中 LLM 保留的 F 理由全部变成
"except-pass 静默吞异常，违反 R-LOG-001 规则语义"——**LLM 已从 round1 的"知识错误"
转为"忠实执行规则语义"**，且它没错：规则 why 白纸黑字写了"pass 属目标缺陷"。
残余分歧的根源从"LLM 缺知识"上移到"规则语义与工程惯例的灰区"，这是设计权衡而非 bug——
自动豁免 pass 会误杀真缺陷形态（GT 中唯一 ? 项 botocore configprovider:640 正是 pass 型），
我们的立场是"故意者请 # noqa 显式声明"。

## Round C：temperature=0 复现实验（2026-09-08，temp 并入缓存键）

同一 26 条队列，贪心解码全量重跑（out/ai_adjudication.t0.json），对照两轮 t=0.1：

| 轮次对 | 共同条目 | 判定翻转 | 翻转率 |
|---|---|---|---|
| round2 ↔ round3（均 t=0.1） | 26 | 7 | **26.9%** |
| round3（t=0.1） ↔ **t=0.0** | 26 | 1 | **3.8%** |

**结论一：温度是噪声主因，贪心解码基本驯服它**——26.9% → 3.8%，
剩余 1 条翻转（werkzeug debug/__init__.py:369）在温度 0 下仍翻，说明服务端
batching 等非确定性还留了个位数尾巴，但量级已可接受。

**结论二（意外收获）：t=0 落在更保守的工作点**——误报击杀从 5 条降到 4 条
（fp_killed=4，kept=22，P=0.056 ≈ round3 的 0.059），贪心解码倾向选高频
"保留"方向。即：**稳定性免费，但用一点点击杀力换**。红线三轮全 0 不变。

**工程采纳**：定级层默认温度保持低位；要复现性论证时用 t=0 数据，
要最优降噪时用 t=0.1 数据——两种工作点都有数，这本身就是分层可控性的体现。

## 勘误纪律自查

上一条消息我在未看明细时预告"P 0.25→0.27"——实际混算口径是 0.033→0.067
（我脑算了类目构成，又错了，且错得方向乐观）。本文档全部数字来自
out/ai_adjudication.json 逐条聚合，脚本可重放验证。
