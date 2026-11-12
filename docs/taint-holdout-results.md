# 污点治理泛化性盲测（三个新仓库）

- 日期：2026-11-12
- 目的：检验 v5/v6 七条通用治理规则是否**泛化**——而非只在参与设计的原六库自证。
- 盲测库：`jinja2` / `itsdangerous` / `markupsafe`（pallets 系，从未参与治理规则设计与原六库标注）。

## 方法

治理前后各跑一次 `TaintTracker`（`tools/taint_holdout.py`），候选逐条读源码上下文盲核验。
三库源码不入库（`realtest-holdout/` 已 gitignore），复现按 clone 字段下载。

## 结果

| 库 | 治理前候选 | 治理后候选 | 说明 |
| --- | --- | --- | --- |
| jinja2 | 1 | 0 | `Markup(self.data)` 误报被规则⑤⑥消除 |
| itsdangerous | 0 | 0 | 签名库，无外部输入→危险 sink 流 |
| markupsafe | 0 | 0 | 转义库，sink 多为安全转义本身 |
| **合计** | **1** | **0** | 误报消除 1，真流丢失 0 |

## 盲测暴露并修复的过宽匹配

`jinja2/nodes.py:619` `TemplateData.as_const` 返回 `Markup(self.data)`：

```python
if eval_ctx.autoescape:
    return Markup(self.data)   # 治理前被误报为 CWE-79
```

- `self.data` 是**模板字面量数据**，非外部输入；
- `autoescape` 开启时才包裹 `Markup`——这恰恰是**防 XSS 的安全机制**，不是漏洞；
- 误染根因：`.data` 属性特征过宽（任意对象属性都撞）+ 变量名 `eval_ctx` 含 `eval` 子串。

→ 驱动 v6 规则⑤（属性特征限定已知外部输入根名）⑥（按完整标识符判定防子串误撞）。

## 结论与诚实口径

- **泛化成立**：治理规则在三个新库上不引入新误报，并消除了盲测暴露的过宽匹配误报。
- **限定**：盲测三库本身外部输入面小（模板/签名/转义库），零候选**不等于**任意库零误报；
  本结论限定为「治理规则在新库上不引入新误报」，**召回率**需更大规模标注另行评测。
- 过滤计数透明入各库 stats（`filtered_const` 等），可复核。

> 复现：`python tools/taint_holdout.py`（需 realtest-holdout/ 三库源码）。
> 原六库治理前后对照见 [taint-eval-results.md](taint-eval-results.md)。
