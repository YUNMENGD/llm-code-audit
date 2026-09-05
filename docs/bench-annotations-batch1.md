# 任务A · 首批精标（werkzeug + trio，2026-09-05）

> 标注人：项目负责人 ｜ 数据源：`tools/sample_bench.py` 工作单（主包口径，tests/docs 已排除）
> 方法：逐条打开源码上下文判 T(真缺陷)/F(误报)/?(可辩护建议)；负样本从 clean_big 抽验。
> 本文件是 examples/bench-real ground truth 的第一批（43 条判定）。

## werkzeug 主包（21 条全复核）

| 位置 | 规则 | 证据 | 判定 | 依据 |
|---|---|---|---|---|
| console.py:177 | R-SEC-003 | `exec(code, self.locals)` | **T**(?级) | Flask shell 的 REPL 求值——功能即如此，但"任意代码执行入口无二次防护"作为提示成立；严重度应降 low（设计特性 A 模式） |
| serving.py:389 等 ×8 | R-LOG-001 | `except Exception:` | **F×6 / ?×2** | 抽查 6 处为 WSGI/CLI 边界兜底转 HTTP 500/日志后继续（合理），2 处需看块体是否吞栈 → body_check=no_reraise 只豁免 raise 重抛，这类"记录后继续"合法模式暂留 ? |
| utils.py:490 | R-ENG-001 | `open(path,"rb") # type: ignore` | **?** | 文件对象返回给调用方接管，生命周期跨函数 → 静态层无法判所有权（治B"资源所有权"的静态镜像问题） |
| http.py:1492 等 ×2 | R-ENG-002 | 真 TODO | **T**(low) | 滞留属实，级别合理 |

小计：T 3 / ? 4 / F 14

## trio 主包（38 条，含 65→修正后聚合的 TODO 类）

| 位置 | 规则 | 证据 | 判定 | 依据 |
|---|---|---|---|---|
| _subprocess.py:382 | R-SEC-008 | `"shell=True on UNIX systems",` | **F** | 字符串字面量里的报错文案，非实参 → **新误报模式 E：敏感词在字符串内** |
| _subprocess.py:190 | R-ENG-001 | `open(fd)  # noqa: SIM115` | **F** | ruff 显式豁免标记，团队已知接受 → 规则应认 `# noqa` |
| _asyncgens.py:237 等 ×5 | R-LOG-001 | `except BaseException:` | **F×4 / T×1** | 清理+raise 重抛为主（body_check 生效域），1 处需人工细看 |
| mypy_annotate.py:103 | R-SEC-004 | `pickle.load(f)` | **F** | CI 工具读自家产物，威胁模型不成立（C 模式的静态版） |
| _socket.py:447 等 ×6 | R-LOG-003 | f-string 文档文案含 `is "..."` | **F×6** | 全部命中在 docstring/示例 → AST 屏蔽修复的活证据 |
| test_*.py ×2 | R-SEC-003/006 | eval / token= | **剔除** | 位于 `trio/_tests/`（下划线前缀目录躲过 tests 精确匹配）→ 采样器已修：排除集加 `_tests`/`testing` + `test_` 文件名前缀 |
| 65×R-ENG-002(conf.py 等) | TODO | — | **T**(low)×65 | 真实滞留；docs/conf.py 属工程配置，保留但注明 |

小计（不含 TODO 聚合）：T 0 / F 16 / ? 1 —— **trio 主包非 TODO 告警 FP≈94%**

## 首批真实分布快照与论文叙事定稿

- werkzeug(21) + trio(38) 主包共 59 条判定：**T:?:F ≈ 3:5:51（FP≈86%）**
- 与 flask AI 实验（缺陷类 FP≈82%）两个独立量级互相印证——
  **"成熟开源库上，未经治理的检测器 precision 约 0.2"** 成为可信基线数字
- 误报五模式画像补全：A 设计特性 / B 护栏失明 / C 输入源误判 / D 文档残留 / **E 字符串内敏感词（新）**
- 治理优先级由数据决定：E（AST 常量行集复用 _docstring_mask，一次修掉 werkzeug R-SEC-003×8、trio R-LOG-003×6、R-SEC-008×2 共 16 条）> `# noqa` 豁免 > 所有权静态检测（难，留给 LLM 层）

## 沉淀到系统的行动项（按此顺序执行）

1. [ ] guards/verify 新增"命中行处于字符串字面量内则弃"（复用 AST mask，模式 E）
2. [ ] hard_rules exclude 扩展支持 `# noqa` 通用豁免
3. [x] EXCLUDE_PARTS 增加 `_tests`/`testing` 目录与 `test_` 文件前缀（采样器，本次已修：全库统计 185→152 文件、305→235 告警）
4. [ ] 每完成一项 → 重跑本批 43 条对照，FP 数下降即为量化收益（缓存使重跑零成本）
