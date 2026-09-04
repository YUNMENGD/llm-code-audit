"""评分统计（干扰样本：变量名含 eval，无任何动态执行）。"""


def average(eval_scores):
    total_eval = sum(eval_scores)
    return {"eval_mean": total_eval / len(eval_scores) if eval_scores else 0.0}
