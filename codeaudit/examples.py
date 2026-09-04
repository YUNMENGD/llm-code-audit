"""Few-shot 校准示例（D13）。

以「示例代码 → 期望输出」对的形式，教模型两件事：
1) 该报什么（正确格式 + 正确修法），
2) 不该报什么（安全的参数化查询 / 交给其他粒度的问题）。
正反例成对给出，比只给正例更能压制误报（"为凑数乱报"）。

- PROMPT_EXAMPLES=0 或 --no-examples 可整体关闭，便于 A/B 对比。
- 示例正文与模板中「校准示例」段重复，属冗余设计：
  模板里的供人工阅读教学，本模块的供运行时注入（可动态开关）。
  两处任一处更新即可，运行时以本模块为准。
"""
from __future__ import annotations

import os

_FUNCTION_EXAMPLES = [
    # 正例：SQL 注入，正确修法为参数化
    (
        "def get_user(uid):\n"
        '    cur.execute("SELECT * FROM users WHERE id=" + str(uid))\n'
        "    return cur.fetchone()",
        '[{"rule_id":"CWE-89","category":"security","severity":"high",'
        '"title":"SQL字符串拼接致注入","line_start":2,"line_end":2,'
        '"function_name":"get_user",'
        '"evidence":"    cur.execute(\\"SELECT * FROM users WHERE id=\\" + str(uid))",'
        '"analysis":"uid 外部可控，未参数化直接拼进 SQL，可注入任意子句。",'
        '"impact":"读取或篡改 users 表。",'
        '"fix":"改参数化：cur.execute(\\"SELECT * FROM users WHERE id=?\\", (uid,))",'
        '"confidence":0.95}]',
    ),
    # 反例：已参数化，安全，必须输出 []
    (
        "def search(kw):\n"
        '    cur.execute("SELECT * FROM items WHERE name=%s", (kw,))\n'
        "    return cur.fetchall()",
        "[]",
    ),
    # 正例：可变默认参数（隐蔽逻辑缺陷）
    (
        "def add_item(x, items=[]):\n"
        "    items.append(x)\n"
        "    return items",
        '[{"rule_id":"LOG-002","category":"logic","severity":"medium",'
        '"title":"可变默认参数跨调用共享","line_start":1,"line_end":3,'
        '"function_name":"add_item","evidence":"def add_item(x, items=[]):",'
        '"analysis":"默认列表定义时创建一次，未传参的调用共享同一对象逐次累积。",'
        '"impact":"返回相互污染的列表，隐蔽数据串台。",'
        '"fix":"items=None 哨兵 + 函数内 items = [] if items is None else items",'
        '"confidence":0.9}]',
    ),
]

_FILE_EXAMPLES = [
    # 正例：跨函数数据流（文件级独有价值）
    (
        "def read_req():\n"
        '    return json.loads(request.body)["path"]\n\n'
        "def handle():\n"
        "    p = read_req()\n"
        "    return open(p).read()",
        '[{"rule_id":"CWE-22","category":"security","severity":"high",'
        '"title":"请求路径未校验直开文件","line_start":6,"line_end":6,'
        '"function_name":"handle","evidence":"    return open(p).read()",'
        '"analysis":"read_req 的外部可控 path 未规范化/白名单校验，跨函数流入 open。",'
        '"impact":"../../etc/passwd 读取任意文件。",'
        '"fix":"os.path.realpath 校验 path 落在允许基目录内再打开。",'
        '"confidence":0.85}]',
    ),
    # 反例：单函数内部问题，文件级不重复报
    ("def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b", "[]"),
]


def examples_enabled(flag: bool | None = None) -> bool:
    """优先级：显式参数 > 环境变量 PROMPT_EXAMPLES > 默认开。"""
    if flag is not None:
        return flag
    return os.getenv("PROMPT_EXAMPLES", "1") != "0"


def format_examples(kind: str, *, limit: int | None = None) -> str:
    """渲染为 Prompt 片段。limit 可截断示例数（控 token 成本）。"""
    pairs = _FUNCTION_EXAMPLES if kind == "function" else _FILE_EXAMPLES
    if limit is not None:
        pairs = pairs[:limit]
    blocks = []
    for i, (code, expected) in enumerate(pairs, 1):
        blocks.append(
            f"## 示例{i}\n输入代码：\n```python\n{code}\n```\n"
            f"期望输出：\n{expected}"
        )
    header = (
        "# 校准示例（示范「该报 / 不该报」的分寸；示例代码与待审代码无关，"
        "不得把示例内容写进结果）"
    )
    return header + "\n\n" + "\n\n".join(blocks)
