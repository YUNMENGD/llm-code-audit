# 评测基准集（D19）

> 目的：量化 precision / recall（验收标准 NFR-1、NFR-2），并测多次运行一致性（NFR-1）。
> 运行：`python -m codeaudit eval examples/bench -d function [--runs 3]`
> 评测口径：按 **(文件, 行区间, 归一化CWE)** 计算 P/R/F1；一条预期问题被
> 系统任一输出命中即算召回；系统输出未命中任何预期即算误报。

## 正样本（含缺陷，6 个文件 / 14 处标注）

| 文件 | 缺陷 | 预期CWE |
|---|---|---|
| pos01_query.py | 查询字符串拼接SQL | CWE-89 |
| pos02_backup.py | 用户输入进 shell | CWE-78 |
| pos03_loader.py | yaml/pickle 反序列化 | CWE-502 |
| pos04_files.py | 路径拼接未校验 | CWE-22 |
| pos05_users.py | 口令 MD5 存储 | CWE-327 |
| pos06_calc.py | 表达式 eval 求值 | CWE-95 |

## 干扰样本（易误报但正确，8 个文件 / 0 处预期）

| 文件 | 表面特征 | 实际安全性 |
|---|---|---|
| neg01_safe_query.py | execute + f-string 风格日志 | 查询参数化；日志无敏感数据 |
| neg02_cli.py | os.environ + subprocess | 固定 argv 白名单命令，输入仅拼进显示文案 |
| neg03_config.py | yaml.load 同名函数 | 已 safe_load + 来源为本地可信配置 |
| neg04_pathlib.py | 路径拼接读文件 | realpath 校验过基目录 |
| neg05_hasher.py | md5 出现 | 仅用于文件去重缓存键，非口令 |
| neg06_eval_name.py | 变量名 eval_score | 纯算术，无动态执行 |
| neg07_secret_like.py | PASSWORD 常量 | 指向环境变量名而非凭据值 |
| neg08_threading.py | threading+global | 有锁保护的计数，无 TOCTOU |

## 标注纪律

- 每个 pos 文件缺陷处带 `# EXPECT: <CWE-id>` 行内注释（评测脚本可人工复核但不读取它，ground truth 在 manifest.json）。
- neg 文件必须"看起来可疑"才有评测价值——平淡无奇的代码测不出误报率。
- 扩充样本：新增文件 → 更新 manifest.json → `python -m codeaudit eval examples/bench --list` 自检。
