# 任务A · 第二批精标（click，2026-09-05）

> 数据源：tools/sample_bench.py 主包口径 ｜ 18 条全量逐处读上下文判定（含 try 块与 finally）
> 模式口径沿用 batch1 的 A/B/C/D/E 画像。

## 判定明细

| 位置 | 规则 | 上下文事实 | 判定 | 归属模式 |
|---|---|---|---|---|
| _compat.py:77 | R-LOG-001 | `__del__` 内 detach 失败 pass | F | 析构清理惯例（bandit 对 except Exception 也不报） |
| _compat.py:124/136/139/149/157/166/170 | R-LOG-001 | **流能力探测**：write(b"")/seek 试一下，失败=不支持该特性，return False/default | F×7 | **探测惯用法（新模式 F1）** |
| _compat.py:543 | R-LOG-001 | isatty() 失败→False | F | F1 |
| _compat.py:561/568 | R-LOG-001 | 缓存 get/set 失败降级，不影响正确性 | F | F2 缓存降级惯例 |
| _winconsole.py:209 | R-LOG-001 | flush 失败继续 buffer.write，有兜底路径 | F | 兜底转换 |
| testing.py:571/581 | R-LOG-001 | del os.environ[key] 失败 pass（键可能本就不存在） | F | 环境清理惯例 |
| utils.py:45 | R-LOG-001 | `_safecall` docstring 自述 "swallows exceptions"，公开设计 | F | **A 设计特性（自我声明）** |
| _termui_impl.py:817 | R-ENG-001 | null=open(/dev/null)，finally: null.close() | F | finally 接管（规则看不见） |
| _termui_impl.py:943 | R-ENG-001 | f=open(/dev/tty)，生成器 finally: f.close() | F | finally 接管（跨 yield） |
| core.py:2304 | R-ENG-002 | 真 XXX 滞留注释 | **T**(low) | — |

## 统计（分类口径，只汇总已逐条核验项）

- click 主包 18 条：**缺陷类 T 0 / F 17；TODO 建议类 T(low) 1** → 缺陷 FP 100%
- 累计三库（werkzeug 21 + trio 38 + click 18 = 77 条，均逐处读过上下文；精确 T/F 以两批明细表为准）：
  - 缺陷类（security/logic，进 P/R 统计）：确认 T 极少（≈2~4，含 werkzeug keyerror 候选与
    exec 类 A 模式边界项）/ ? ≈5 / 其余全 F → **FP≈85~90%**
  - 建议类（TODO 等，不计 P/R）：T(low) ≈32（trio 29 + werkzeug 2 + click 1），真实但低价值
  - 单库缺陷 FP：werkzeug 63% / trio 94% / click 100%（越成熟噪声占比越高）
- **新模式 F1「探测惯用法」**：`try: 试操作 except Exception: return False/default` —— CLI/IO 库的
  能力探测范式，click 10 条 + werkzeug/testing 若干。R-LOG-001 语义需收窄（见行动项）
- R-ENG-001 的盲区确认：资源在 finally/下游 close 即合法，"未用 with"当且仅当
  找不到任何关闭路径才该报 → 块感知扩展

## 行动项（batch2 新增，按性价比）

1. [ ] R-LOG-001 语义对齐 bandit：`except Exception:` 只有"pass/return 常量且无日志"且非探测语境才报；
   实现为 body_check=probe_pattern（except 体仅 return False/default/None/pass → 豁免）。
   预期收益：click 直清 10 条、werkzeug 清 8 条、六库 R-LOG-001 31→≈5 条真实吞异常
2. [ ] R-ENG-001 加 body_check=managed_resource：向后扫 30 行内出现
   `finally: x.close()` / `if f is not None: f.close()` 即豁免。预期六库 −4 条
3. [x] 标注累计达 77 条，三库画像稳定（FP 88~94%）——"成熟库未治理检测器 precision≈0.1"
   写进论文基线；剩余 requests/httpcore/botocore 等待跑（或团队用工作单自行勾选）
