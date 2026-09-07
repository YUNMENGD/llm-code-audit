"""bench-real 回归测试（任务A 标注 → 持续保证）。

把 80 条人工核验 ground truth 固化为 pytest 用例：任何人改 rules.py /
knowledge/ 后跑一遍，即时发现两类事故——
  ① 红线：真缺陷（T）被新豁免误杀（lost_T 必须恒为 0）
  ② 回退：某库 precision 跌破冻结值（说明治理失效或规则引入新噪声）

与 docs/ai-adjudication-results.md 的三轮漏斗数据同源（FROZEN 即 round3 实测）。
realtest/ 库源码缺失时整体 skip（clone 指引见 bench-real/*.json 的 meta.clone）。

运行：pytest tests/test_bench_real.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codeaudit.realeval import LIBS, _REALTEST, evaluate, load_gt  # noqa: E402

pytestmark = pytest.mark.skipif(
    not _REALTEST.exists(),
    reason="realtest/ 不存在：按 bench-real/*.json 的 meta.clone 下载库源码")

# round3 实测冻结值（2026-09-07，exp/ai-adjudication @ bf5245f）。
# 有意改进规则导致数值变化时，跑 python -m codeaudit real-eval 确认后更新此表，
# 并同步 docs/ai-adjudication-results.md——改测试必须带着数据依据，不许顺手放宽。
FROZEN = {
    "botocore":   {"precision": 0.833, "kept_T": 15},
    "click":      {"precision": 0.1,   "kept_T": 1},
    "flask":      {"precision": 0.0,   "kept_T": 0},
    "requests":   {"precision": 1.0,   "kept_T": 9},
    "werkzeug":   {"precision": 0.333, "kept_T": 3},
}


@pytest.fixture(scope="module")
def results():
    return {lib: evaluate(lib) for lib in LIBS}


@pytest.mark.parametrize("lib", LIBS)
def test_gt_file_exists(results, lib):
    r = results[lib]
    assert "error" not in r, f"{lib}: {r.get('error')}"


@pytest.mark.parametrize("lib", LIBS)
def test_zero_false_kill_redline(results, lib):
    """红线：治理不允许吃掉任何一个人工核验的真缺陷。"""
    r = results[lib]["current"]
    assert r["lost_T"] == 0, (
        f"{lib}: {r['lost_T']} 条真缺陷被误杀！最近改动的豁免规则过度抑制")


@pytest.mark.parametrize("lib", LIBS)
def test_kept_T_matches_frozen(results, lib):
    r = results[lib]
    assert r["current"]["kept_T"] == FROZEN[lib]["kept_T"], (
        f"{lib}: 真缺陷保留数 {r['current']['kept_T']} != 冻结 "
        f"{FROZEN[lib]['kept_T']}（GT 或扫描行为变了，先 real-eval 复核）")


@pytest.mark.parametrize("lib", LIBS)
def test_precision_no_regression(results, lib):
    cur = results[lib]["current"]["precision"]
    frozen = FROZEN[lib]["precision"]
    assert cur is not None and cur >= frozen - 1e-9, (
        f"{lib}: precision {cur} < 冻结值 {frozen}，治理回退")


@pytest.mark.parametrize("lib", LIBS)
def test_precision_anchored_to_gt(results, lib):
    """交叉锚定：T+F 计数之和必须等于 GT 中 T+F 标注数（防 GT 被误编辑）。"""
    gt = load_gt(lib)
    t = sum(1 for a in gt["annotations"] if a["verdict"] == "T")
    f = sum(1 for a in gt["annotations"] if a["verdict"] == "F")
    base = results[lib]["baseline"]
    assert (base["T"], base["F"]) == (t, f), f"{lib}: GT 文件与 baseline 不一致"
