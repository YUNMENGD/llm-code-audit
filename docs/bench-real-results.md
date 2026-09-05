# 真实开源库基准结果（bench-real · click+werkzeug 双库，2026-09-05）

> ⚠️ **勘误在先**：我曾宣称"click 治理后 precision=1.000、消除 17 条误报"——那是跑
> `real-eval` 之前按标注文档"预期收益"写的**未验证推算**，实测是 precision 0.100、
> 消除 8 条。本文所有数字以机器实测为准；方法论就此固化：**没有 diff 复核不下结论**。
> （这条教训连同治理轨迹值得写进论文的工程过程一节。）

## 1. 工具与方法论

- **入口**：`python -m codeaudit real-eval [库名…]`（`codeaudit/realeval.py`）
- **原理**：对"治理前基线"的逐行人工判定（ground truth），把**当前**静态扫描结果
  逐条比对，输出：precision 前后、按误报模式的消除统计、**真缺陷误杀检测（lost_T）**、
  基线外新增告警
- **ground truth 位置**：`bench-real/click.json`（18 条）+ `bench-real/werkzeug.json`
  （22 条），逐行 T/F/? 与判定依据；出处 `docs/bench-annotations-batch1/2.md` 的
  逐处源码核验 + 本次 werkzeug 全量导出复核
- **为什么真实库只能测 precision**：真缺陷无法穷举标注（没人能断言 click 没有未知
  缺陷），recall 的分母不存在。合成基准管 recall（保下限）、真实基准管 precision
  （保上限），两把尺子各司其职——这是双基准设计的核心论据
- 成本：纯本地静态，零额度，单库秒级 → 任何治理改动的专用回归尺

## 2. 实测结果（治理链全开：E 遮蔽 + noqa + F1 探测 + RES 接管 + RERAISE + NAME）

### click（18 条基线，T1/F17）

| 指标 | 治理前 | 治理后 |
|---|---|---|
| 告警数 | 18 | 10 |
| **precision** | **0.056** | **0.100** |
| 消除误报 | — | 8（F1×5 + RES×2 + F2×1） |
| 真缺陷误杀 | — | **0** ✅ |

### werkzeug（22 条基线，T3/F16/?3——比 click 难，含 debug REPL）

| 指标 | 治理前 | 治理后 |
|---|---|---|
| 告警数 | 22 | 13 |
| **precision** | **0.158** | **0.300** |
| 消除误报 | — | 9（**NAME×6** + RES×1 + F1×1 + RERAISE×1） |
| 真缺陷误杀 | — | **0** ✅（真 exec×2 + TODO×2 全保留） |

**NAME 模式（werkzeug 揭示的第六种误报）**：`def eval(self,...)` / `self.console.eval()`——
框架把 eval/exec 用作**方法名**，`\b` 词边界挡不住属性调用。修法：
`(?<![.\w])(?<!def )` 双负向断言，只留 builtin 真调用；7 项正则测试钉边界。
此模式此前把 werkzeug"真 exec"虚报成 11 条，batch2 里"exec×11 保留"的表述实际混入
6 条 NAME 误报——bench 化逐行核验把它挤掉了。

## 3. 残留（click 9 + werkzeug 7）：确定性层的"设计天花板"，不是治理失败

| 形态 | 条数 | 为何保留（有意为之） |
|---|---|---|
| `except Exception: pass`（清理/兜底语境） | click 7 + wz 5 | "静默吞异常"是申报书声明的目标缺陷类；bandit 亦作独立低危项（B110）。作者意图应由 `# noqa` 显式声明，工具不替人猜 |
| 嵌套 `try:` 探测 / 调用式降级 `return fallback_repr()` | 2+1 | probe 白名单不穿透嵌套、不豁免函数调用式降级（再扩就要猜语义了） |
| 跨函数资源所有权（?） | wz 2 | open 句柄返回给调用方关闭，静态层无数据流可判，LLM 层职责 |

**政策分叉维持不放宽**：若豁免"except Exception: pass"，click FP 预期 9→2，但业务代码里
真有吞写盘失败的形态会被一起放掉——放掉即真实漏报。这类留给 LLM 语义层，
"静态高召回线索网 → LLM 定级"的架构分工正是靠这批残留数据论证的。

## 4. 复用与扩展

```bash
# 库不入库（体积+许可），复现者自行下载到 realtest/：
git clone --depth 1 https://github.com/pallets/click.git realtest/click
python -m codeaudit real-eval click      # 不带参数 = 评测 bench-real/ 全部已标库
```

扩展路线：~~werkzeug~~（已入库）→ flask（real-ai-probe 实验的 12 条核验表转
manifest，但那份基线含 NAME 修正前数据，转写时先重扫）→ requests/botocore
（待逐行标注）→ trio（batch1 里 TODO 是聚合行，需逐行重拆后才能进机器化
ground truth——聚合数字不进 bench-real，宁缺毋滥）。
