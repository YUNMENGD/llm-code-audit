# 真实开源库基准结果（bench-real · 首批 click，2026-09-05）

> ⚠️ **勘误在先**：我曾宣称"click 治理后 precision=1.000、消除 17 条误报"——那是跑
> `real-eval` 之前按标注文档"预期收益"写的**未验证推算**，实测是 precision 0.100、
> 消除 8 条。本文所有数字以机器实测为准；方法论就此固化：**没有 diff 复核不下结论**。
> （这条教训连同治理轨迹值得写进论文的工程过程一节。）

## 1. 工具与方法论

- **入口**：`python -m codeaudit real-eval [库名…]`（`codeaudit/realeval.py`）
- **原理**：对"治理前基线"的逐行人工判定（ground truth），把**当前**静态扫描结果
  逐条比对，输出：precision 前后、按误报模式的消除统计、**真缺陷误杀检测（lost_T）**、
  基线外新增告警
- **ground truth 位置**：`bench-real/click.json`（18 条逐行 T/F，出处
  `docs/bench-annotations-batch2.md` 的逐处源码核验）
- **为什么真实库只能测 precision**：真缺陷无法穷举标注（没人能断言 click 没有未知
  缺陷），recall 的分母不存在。合成基准管 recall（保下限）、真实基准管 precision
  （保上限），两把尺子各司其职——这是双基准设计的核心论据
- 成本：纯本地静态，零额度，单库秒级 → 任何治理改动的专用回归尺

## 2. click 实测（治理链全开：E 字符串遮蔽 + noqa 豁免 + F1 探测 + RES 接管）

| 指标 | 治理前 | 治理后 |
|---|---|---|
| 告警数 | 18 | 10 |
| T / F | 1 / 17 | 1 / 9 |
| **precision** | **0.056** | **0.100** |
| 真缺陷误杀 | — | **0** ✅ |
| 基线外新增 | — | 0 |

消除的 8 条按模式：**F1 探测×5 + RES finally接管×2 + F2 缓存降级×1**——与治理项
一一咬合；werkzeug 真 exec×11 保留测试证明零误伤。

## 3. 残留 9 条：确定性层的"设计天花板"，不是治理失败

全部是 `except Exception:`，块体为：

| 形态 | 条数 | 为何保留（有意为之） |
|---|---|---|
| 体为 `pass` | 7 | "静默吞异常"是申报书声明的目标缺陷类（`_safecall` 类设计特性也在此列）。bandit 同样将 try/except/pass 作独立低危项（B110/B112 思路）。作者的意图应用 `# noqa` 显式声明，工具不替人猜 |
| 体为嵌套 `try:` | 2 | `_compat` 的探测外层——probe_check 不穿透嵌套（保守边界，当时明示"宁可留报不误删"） |

**政策分叉（待负责人拍板）**：若把 F1 放宽为"`except Exception: pass` 也豁免"，
click 的 FP 预期 9→2；但"显式 Exception+pass"在业务代码里也有真吞错误的形态
（如吞文件写失败），静态层放掉是真实损失。我的建议：**不放宽**，把这类判定留给
LLM 语义层——这正是"静态层高召回线索网 → LLM 定级"分工存在的理由，而残留构成
数据本身就是这个架构论证的最佳实证。

## 4. 复用与扩展

```bash
# 库不入库（体积+许可），复现者自行下载到 realtest/：
git clone --depth 1 https://github.com/pallets/click.git realtest/click
python -m codeaudit real-eval click      # 不带参数 = 评测 bench-real/ 全部已标库
```

扩展顺序：werkzeug（batch1 已有逐行判定，直接转 manifest）→ flask（real-ai-probe
实验的 12 条核验表）→ trio（batch1 里 TODO 是聚合行，需逐行重拆后才能进机器化
ground truth——聚合数字不进 bench-real，宁缺毋滥）。
