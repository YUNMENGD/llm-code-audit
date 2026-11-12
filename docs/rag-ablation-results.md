# RAG 消融实验：关键词 vs 向量融合

- 日期：2026-11-12 · k=5
- 真值：bench-real 六库人工核验 T/F 标注，规则→知识条目经 cwe_map 映射（映射目标必须真实存在于知识库，坏映射已剔除）
- 窗口外用例：106 条 T/F 告警行落在文件级 3000 字符打分窗之外，单列不计入 recall 分母（线上文件级审计同样看不到这些行；函数级口径可覆盖）

| 查询口径 | 臂 | recall@k（T 命中） | F 条目 top-k 命中率 | 耗时 |
| --- | --- | --- | --- | --- |
| 文件窗（前3000字符） | 关键词 | 0.714 (5/7) | 1.0 (6/6) | 0.0s |
| 文件窗（前3000字符） | 向量融合 | ⚠️暂未获取（无 embeddings 端点） | — | — |
| 函数窗（所在函数全文） | 关键词 | 0.592 (29/49) | 0.917 (55/60) | 0.0s |
| 函数窗（所在函数全文） | 向量融合 | ⚠️暂未获取（无 embeddings 端点） | — | — |

## 分库明细（file 窗 · 关键词臂）

| 库 | T 命中/总数 | F 命中/总数 |
| --- | --- | --- |
| botocore | 1/1 | 1/1 |
| click | 0/0 | 2/2 |
| requests | 3/3 | 0/0 |
| trio | 1/3 | 3/3 |

### file 窗未命中的 T 用例（向量臂的潜在增益点）

- trio/_core/_io_kqueue.py:82 R-ENG-002→STY-006
- trio/_dtls.py:56 R-ENG-002→STY-006

## 分库明细（func 窗 · 关键词臂）

| 库 | T 命中/总数 | F 命中/总数 |
| --- | --- | --- |
| botocore | 13/13 | 5/5 |
| click | 0/1 | 15/17 |
| flask | 0/0 | 3/3 |
| requests | 1/6 | 3/3 |
| trio | 13/26 | 13/16 |
| werkzeug | 2/3 | 16/16 |

### func 窗未命中的 T 用例（向量臂的潜在增益点）

- click/core.py:2304 R-ENG-002→STY-006
- requests/adapters.py:715 R-ENG-002→STY-006
- requests/auth.py:213 R-ENG-002→STY-006
- requests/auth.py:247 R-ENG-002→STY-006
- requests/auth.py:252 R-ENG-002→STY-006
- requests/models.py:1016 R-ENG-002→STY-006
- trio/_channel.py:626 R-ENG-002→STY-006
- trio/_channel.py:632 R-ENG-002→STY-006
- trio/_core/_io_windows.py:853 R-ENG-002→STY-006
- trio/_core/_io_windows.py:855 R-ENG-002→STY-006
- trio/_core/_io_windows.py:902 R-ENG-002→STY-006
- trio/_core/_run.py:2923 R-ENG-002→STY-006
- trio/_core/_run.py:2930 R-ENG-002→STY-006
- trio/_dtls.py:1026 R-ENG-002→STY-006
- trio/_dtls.py:1313 R-ENG-002→STY-006
- trio/_repl.py:100 R-ENG-002→STY-006
- trio/_repl.py:113 R-ENG-002→STY-006
- trio/_subprocess.py:373 R-ENG-002→STY-006
- trio/_util.py:123 R-ENG-002→STY-006
- werkzeug/http.py:1492 R-ENG-002→STY-006

> 口径说明：本实验测「检索层把正确弹药送进 top-k 的能力」，不是端到端 precision；F 命中率仅作参考——veto 机制会剔除越界条目，两臂同口径。窗口外用例单列是诚实口径：文件级打分窗截断是线上真实行为，函数级粒度可覆盖长文件后部的告警行。向量臂数据缺失时不得以训练知识补全。
