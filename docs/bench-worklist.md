# 任务A标注工作单（静态预筛 · 自动生成）

> 生成：tools/sample_bench.py ｜ 数据源：realtest/ 十个真实开源库
> 复核规则：每条告警标 T(真缺陷)/F(误报)/?；另从 clean_big 里抽等量文件标 N(确认无缺陷)。
> F 的形态记入 docs/fp-governance-experiment.md 的四模式(A/B/C/D)，反哺治理。

## requests（realtest\requests\src\requests，5 文件有告警 / 12 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| auth.py | 179 | R-SEC-007 | MD5/SHA1 用于口令或签名 | medium | ☐T ☐F ☐? |
| auth.py | 187 | R-SEC-007 | MD5/SHA1 用于口令或签名 | medium | ☐T ☐F ☐? |
| auth.py | 237 | R-SEC-007 | MD5/SHA1 用于口令或签名 | medium | ☐T ☐F ☐? |
| auth.py | 213 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| auth.py | 247 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| auth.py | 252 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _types.py | 60 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _types.py | 61 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| models.py | 687 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| models.py | 1016 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| adapters.py | 715 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| hooks.py | 29 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  __init__.py, api.py, cookies.py

## botocore（realtest\botocore\botocore，18 文件有告警 / 27 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| client.py | 99 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| client.py | 685 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| client.py | 763 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| response.py | 100 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| response.py | 117 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| response.py | 201 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| compat.py | 146 | R-SEC-007 | MD5/SHA1 用于口令或签名 | medium | ☐T ☐F ☐? |
| compat.py | 162 | R-SEC-007 | MD5/SHA1 用于口令或签名 | medium | ☐T ☐F ☐? |
| credentials.py | 2073 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| credentials.py | 1948 | R-LOG-003 | is 比较字面量 | low | ☐T ☐F ☐? |
| endpoint.py | 176 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| endpoint.py | 349 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| exceptions.py | 697 | R-LOG-003 | is 比较字面量 | low | ☐T ☐F ☐? |
| exceptions.py | 773 | R-LOG-003 | is 比较字面量 | low | ☐T ☐F ☐? |
| utils.py | 3402 | R-SEC-007 | MD5/SHA1 用于口令或签名 | medium | ☐T ☐F ☐? |
| utils.py | 2342 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| args.py | 995 | R-LOG-003 | is 比较字面量 | low | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  __init__.py, awsrequest.py, config.py

## click（realtest\click\src\click，6 文件有告警 / 18 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| _compat.py | 77 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 124 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 136 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 139 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 149 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 157 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _termui_impl.py | 817 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| _termui_impl.py | 943 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| testing.py | 571 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| testing.py | 581 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _winconsole.py | 209 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| core.py | 2304 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| utils.py | 45 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  _textwrap.py, decorators.py, exceptions.py

## pip（realtest\pip\src\pip，37 文件有告警 / 57 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| session.py | 292 | R-SEC-005 | verify=False 关闭 TLS 证书校验 | high | ☐T ☐F ☐? |
| session.py | 303 | R-SEC-005 | verify=False 关闭 TLS 证书校验 | high | ☐T ☐F ☐? |
| session.py | 160 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| session.py | 221 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| installer.py | 62 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| installer.py | 169 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| installer.py | 205 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| prepare.py | 662 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| prepare.py | 736 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| prepare.py | 774 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| base.py | 26 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| base.py | 92 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| base_command.py | 164 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| base_command.py | 226 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| index_command.py | 206 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| index_command.py | 215 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| install.py | 663 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| install.py | 644 | R-LOG-003 | is 比较字面量 | low | ☐T ☐F ☐? |
| configuration.py | 338 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| configuration.py | 388 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  autocompletion.py, parser.py, progress_bars.py

## httpcore（realtest\httpcore\httpcore，0 文件有告警 / 0 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  connection.py, connection_pool.py, http11.py

## typer（realtest\typer\typer，11 文件有告警 / 40 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| _compat.py | 68 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 115 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 124 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 128 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 478 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| _compat.py | 502 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| params.py | 27 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| params.py | 43 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| params.py | 92 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| params.py | 108 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| params.py | 267 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| params.py | 457 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| models.py | 292 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| models.py | 401 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| models.py | 418 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| models.py | 529 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| models.py | 687 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| core.py | 263 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| core.py | 455 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| core.py | 513 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| core.py | 674 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _termui_impl.py | 363 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| _termui_impl.py | 493 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| _termui_impl.py | 408 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _completion_classes.py | 52 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _completion_classes.py | 130 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _completion_classes.py | 172 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _completion_shared.py | 76 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _completion_shared.py | 133 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| testing.py | 251 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| testing.py | 261 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  exceptions.py, formatting.py, parser.py

<<<<<<< HEAD
## kombu（realtest\kombu\t，1 文件有告警 / 1 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| conftest.py | 81 | R-LOG-002 | 可变默认参数 | medium | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  common.py, mocks.py, conftest.py
=======
## kombu（realtest\kombu\t，16 文件有告警 / 32 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| test_redis.py | 3391 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_redis.py | 3402 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_redis.py | 3422 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_redis.py | 3433 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_redis.py | 128 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| test_SQS_SNS.py | 376 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_SQS_SNS.py | 501 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_SQS_SNS.py | 1673 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_SQS_SNS.py | 2046 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_qpid.py | 1427 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_qpid.py | 1474 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_qpid.py | 1509 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_qpid.py | 1513 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_filesystem.py | 47 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| test_filesystem.py | 206 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| test_filesystem.py | 301 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| test_sqs.py | 19 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_sqs.py | 54 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_serialization.py | 268 | R-SEC-004 | pickle 反序列化不可信数据 | high | ☐T ☐F ☐? |
| test_serialization.py | 269 | R-SEC-004 | pickle 反序列化不可信数据 | high | ☐T ☐F ☐? |
| test_div.py | 28 | R-SEC-004 | pickle 反序列化不可信数据 | high | ☐T ☐F ☐? |
| test_div.py | 54 | R-SEC-004 | pickle 反序列化不可信数据 | high | ☐T ☐F ☐? |
| test_functional.py | 76 | R-SEC-004 | pickle 反序列化不可信数据 | high | ☐T ☐F ☐? |
| test_functional.py | 159 | R-SEC-004 | pickle 反序列化不可信数据 | high | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  common.py, test_mongodb.py, test_py_amqp.py
>>>>>>> origin/main

## alembic（realtest\alembic\alembic，16 文件有告警 / 21 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| mssql.py | 330 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| mssql.py | 351 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| mssql.py | 153 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| mssql.py | 389 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| mysql.py | 225 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| mysql.py | 289 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| env.py | 116 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| env.py | 117 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| constraints.py | 405 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| render.py | 795 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| postgresql.py | 146 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| base.py | 185 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| batch.py | 268 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  api.py, server_defaults.py, tables.py

## werkzeug（realtest\werkzeug\src\werkzeug，11 文件有告警 / 21 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| __init__.py | 138 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| __init__.py | 139 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| __init__.py | 398 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| __init__.py | 369 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| file_storage.py | 128 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| file_storage.py | 115 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| file_storage.py | 188 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| console.py | 177 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| console.py | 213 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| console.py | 178 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| repr.py | 220 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| repr.py | 237 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| repr.py | 260 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| tbtools.py | 391 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| tbtools.py | 392 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |
| http.py | 1492 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| lint.py | 223 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| rules.py | 736 | R-SEC-003 | eval / exec 动态执行 | critical | ☐T ☐F ☐? |

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  _internal.py, _reloader.py, accept.py

<<<<<<< HEAD
## trio（realtest\trio\src\trio，17 文件有告警 / 38 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
=======
## trio（realtest\trio\src\trio，35 文件有告警 / 77 条）

| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |
|---|---|---|---|---|---|
| test_dtls.py | 208 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| test_dtls.py | 541 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| test_dtls.py | 653 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| test_dtls.py | 697 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| test_dtls.py | 726 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| test_dtls.py | 757 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
>>>>>>> origin/main
| _dtls.py | 56 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _dtls.py | 220 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _dtls.py | 421 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _dtls.py | 428 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _dtls.py | 1026 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _dtls.py | 1313 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _repl.py | 28 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _repl.py | 78 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _repl.py | 100 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _repl.py | 113 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _repl.py | 117 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_kqueue.py | 82 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_kqueue.py | 94 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_kqueue.py | 99 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_kqueue.py | 163 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _run.py | 183 | R-LOG-003 | is 比较字面量 | low | ☐T ☐F ☐? |
| _run.py | 2667 | R-LOG-003 | is 比较字面量 | low | ☐T ☐F ☐? |
| _run.py | 2923 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _run.py | 2930 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _subprocess.py | 382 | R-SEC-008 | subprocess shell=True | high | ☐T ☐F ☐? |
| _subprocess.py | 190 | R-ENG-001 | 文件/连接未用 with 管理 | low | ☐T ☐F ☐? |
| _subprocess.py | 373 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _subprocess.py | 1122 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
<<<<<<< HEAD
| _io_windows.py | 853 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_windows.py | 855 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_windows.py | 902 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _channel.py | 626 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _channel.py | 632 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _asyncgens.py | 237 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
=======
| test_threads.py | 880 | R-SEC-006 | 疑似硬编码密钥/口令 | high | ☐T ☐F ☐? |
| test_threads.py | 244 | R-LOG-001 | 裸 except 吞掉所有异常 | medium | ☐T ☐F ☐? |
| test_threads.py | 573 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| test_threads.py | 1140 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_windows.py | 853 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_windows.py | 855 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
| _io_windows.py | 902 | R-ENG-002 | TODO/FIXME 未清理 | low | ☐T ☐F ☐? |
>>>>>>> origin/main

**负样本候选**（>150 行零告警，抽验确认确实干净）：
  _abc.py, _exceptions.py, _generated_io_kqueue.py

## 汇总

<<<<<<< HEAD
- 待复核文件 ≈ **152**，静态告警 **235** 条
- 规则命中分布（复核重点从高到低）：
  - R-ENG-002: 83
  - R-LOG-001: 32
=======
- 待复核文件 ≈ **185**，静态告警 **305** 条
- 规则命中分布（复核重点从高到低）：
  - R-ENG-002: 90
  - R-LOG-001: 35
  - R-SEC-006: 18
>>>>>>> origin/main
  - R-SEC-003: 11
  - R-ENG-001: 8
  - R-LOG-003: 7
  - R-SEC-007: 6
<<<<<<< HEAD
  - R-SEC-006: 3
  - R-SEC-005: 2
=======
  - R-SEC-004: 6
>>>>>>> origin/main
- 建议首批精标 25~30 文件：告警最密的 top 库各取 2~3 文件 + 等量负样本
