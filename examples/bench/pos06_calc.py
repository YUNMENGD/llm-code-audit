"""报表公式求值（含 1 处缺陷）。"""


def evaluate(formula: str, row):
    # EXPECT: CWE-95
    return eval(formula, {"__builtins__": {}}, {"row": row})
