# 真实开源库静态检查实验（阶段三 · 任务 A 前哨）

> 日期：2026-09-05 ｜ 对象：python-dotenv（theskumar/python-dotenv，GitHub 16k+ star 的成熟库）
> 方式：`git clone --depth 1` → 仅审计 `src/dotenv` 包目录（8 个 py 文件）→ `python -m codeaudit check`
> 说明：本实验只用免费的静态规则（不耗模型额度），是 examples/bench 合成基准之外，
> 首次在**高质量真实代码**上度量误报率。论文可引作"成熟库上的 false positive 压力测试"。

## 结果

| 版本 | 检出 | 人工判定 | precision（缺陷类） |
|---|---|---|---|
| 修复前 | 3（2 中危 1 低危） | 2 条 R-LOG-001 均为误报：`except BaseException: cleanup; raise` 是清理重抛的防御惯用法（main.py:156/185）；148 行 open 在条件接管保护内 | 0/2 |
| 修复后 | 1（低危建议级） | 仅剩 R-ENG-001 报 `open()` 未用 with——属可辩护的改进建议，评测口径 v0.4 中 engineering 类不参与 P/R | 缺陷误报 0 |

## 修复内容（本 PR 代码变更）

1. **rules.py：`_block_reraises()`** —— R-LOG-001 获得块级感知：命中 `except (BaseException|Exception)?` 后，
   向下扫描同缩进块体，发现任意 `raise`（含清理语句之后）即豁免。对齐 bandit `try_except_pass` 的语义。
2. **hard_rules.json：`"body_check": "no_reraise"`** —— 规则库声明式启用，其他规则不受影响。
3. 方向性保守评估：豁免仅针对"重抛传播"这一种可客观证明的模式，不做语义猜测；
   练习集 buggy_notes.py:98 的裸 `except: pass` 真缺陷仍稳定检出，101 项离线测试无回归。

## 结论与下一步

- **合成基准会系统性低估误报难度**：bench 负样本是我们自己设计的，而成熟开源库的
  "高级防御写法"（清理重抛、条件接管资源、带注释的非安全哈希）才是真实世界的误报主产区。
  这与 fp-governance-experiment.md 的 P=0.857 并不矛盾——那是基准内成绩，真实分布待任务 A 建集重测。
- 下一步（任务书 A 项正式开工时）：
  1. 多采几个不同风格的库（requests / flask / httpx / black），建 20~30 项目标注集
  2. 跑完整 AI 审计（含 verify + guards + cross-review）输出真实 P/R/F1 四指标表
  3. 把"清理重抛"这类防御惯用法沉淀进 knowledge/defects（LOG 类目，教 LLM 也别报）

## 追加：四库批量复扫（本 PR 的 AST 文档串屏蔽 + 词边界修复后）

免费静态层，修复前后告警数：

| 库 | 修复前 | 修复后 | 剩余告警性质 |
|---|---|---|---|
| python-dotenv | 3 | 1 | 合法资源管理模式（建议级，不计缺陷 FP） |
| flask | 8 | 6 | `eval(compile())` 真实动态执行、sha1 签名、真裸 except |
| httpx | 5 | 4 | sha1 摘要、两处真 `except Exception: return False`、TODO |
| black | 25 | 18 | `pickle.load`、eval 系真实代码 + 大量 TODO 注释（本就应报） |

**消除的**：flask docstring 里的 `password="a secret"` / `debug=True` 示例、black 里
`if is_star_except:` 撞 except 正则、注释行里的 `is "..."`。**保留的**：真代码调用真敏感 API。

### 边界原则：静态层"宁报不压制"

剩余告警刻意不自动过滤。理由：`eval(compile(src))`、`pickle.load` 在框架里是
**真实存在的危险原语**，只是此处用法合法（输入可信/受控）。静态规则无法可靠判断
"输入是否可信"——这正是交给 LLM 数据流分析和人工复核的职责。若静态层用更多正则
自压制，会把真漏洞一起压掉（漏报代价 ≫ 误报）。定位分工：
**静态层=高召回线索网 → verify/guards=消确定性误报 → LLM/双模型=语义定级 → 人=终判。**
论文里这是"分层降噪、职责分离"设计的实证依据。
