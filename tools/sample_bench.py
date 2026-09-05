# -*- coding: utf-8 -*-
"""任务A采样器：对候选库跑静态预筛，输出标注工作单（免费、离线）。

用法：python tools/sample_bench.py            # 默认10库
      python tools/sample_bench.py requests click
产出：docs/bench-worklist.md —— 按告警密度排序的文件清单 + 每文件告警明细，
      标注人只需复核这些点（真/误报二选一），不必通读全库。
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codeaudit import rules as RL          # noqa: E402
from codeaudit.models import Severity      # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent / "realtest"
EXCLUDE_PARTS = {"tests", "test", "testing", "_vendor", "docs", "doc",
                 ".venv", "node_modules", "scripts", "example", "examples"}

LIBS = ["requests", "botocore", "click", "pip", "httpcore", "typer",
        "kombu", "alembic", "werkzeug", "trio"]


def pkg_dir(lib: str) -> Path | None:
    """定位库的主包目录：在 src/ 与仓库根两层里找含 __init__.py 的包，
    排除 tests/docs/examples 等噪声名；多个候选时优先更深路径（src/<pkg>）。"""
    base = ROOT / lib
    cands: list[Path] = []
    for root in (base, base / "src"):
        if not root.exists():
            continue
        for d in sorted(root.iterdir()):
            if d.is_dir() and (d / "__init__.py").exists() \
                    and d.name.lower() not in EXCLUDE_PARTS:
                cands.append(d)
    if not cands:
        return None
    # 优先 src 下的包（层级更深），其次仓库根
    return max(cands, key=lambda p: (len(p.parts), str(p)))


def scan(pkg: Path):
    all_rules = RL.load_rules()
    per_file: dict[Path, list] = {}
    clean_big: list[Path] = []
    sev_rank = {Severity.CRITICAL: 3, Severity.HIGH: 2,
                Severity.MEDIUM: 1, Severity.LOW: 0}
    for f in sorted(pkg.rglob("*.py")):
        if EXCLUDE_PARTS & {p.lower() for p in f.parts}:
            continue
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = RL.scan_source(src, all_rules, str(f))
        if hits:
            per_file[f] = sorted(hits, key=lambda h: -sev_rank[h.severity])
        elif len(src.splitlines()) > 150:
            clean_big.append(f)          # 干净大文件 = 负样本候选
    return per_file, clean_big[:3]


def main(libs: list[str]) -> None:
    out = ["# 任务A标注工作单（静态预筛 · 自动生成）", "",
           "> 生成：tools/sample_bench.py ｜ 数据源：realtest/ 十个真实开源库",
           "> 复核规则：每条告警标 T(真缺陷)/F(误报)/?；另从 clean_big 里抽等量文件标 N(确认无缺陷)。",
           "> F 的形态记入 docs/fp-governance-experiment.md 的四模式(A/B/C/D)，反哺治理。", ""]
    total_files = total_hits = 0
    rule_counter: Counter = Counter()
    for lib in libs:
        pkg = pkg_dir(lib)
        if pkg is None:
            out.append(f"## {lib}\n\n未找到包目录，跳过。\n")
            continue
        res, clean_big = scan(pkg)
        hits_files = res
        n_hits = sum(len(v) for v in hits_files.values())
        total_files += len(hits_files) + len(clean_big)
        total_hits += n_hits
        out += [f"## {lib}（{pkg.relative_to(ROOT.parent)}，"
                f"{len(hits_files)} 文件有告警 / {n_hits} 条）", ""]
        ranked = sorted(hits_files.items(), key=lambda kv: -len(kv[1]))[:8]
        out += ["| 文件 | 行 | 规则 | 标题 | 级别 | 判定 |", "|---|---|---|---|---|---|"]
        for f, hits in ranked:
            for h in hits[:6]:
                rule_counter[h.rule_id] += 1
                out.append(f"| {f.name} | {h.line_start} | {h.rule_id} "
                           f"| {h.title} | {h.severity.value} | ☐T ☐F ☐? |")
        if clean_big:
            out += ["", "**负样本候选**（>150 行零告警，抽验确认确实干净）：",
                    "  " + ", ".join(p.name for p in clean_big)]
        out.append("")
    out += ["## 汇总", "",
            f"- 待复核文件 ≈ **{total_files}**，静态告警 **{total_hits}** 条",
            "- 规则命中分布（复核重点从高到低）：",
            *[f"  - {r}: {c}" for r, c in rule_counter.most_common(8)],
            "- 建议首批精标 25~30 文件：告警最密的 top 库各取 2~3 文件 + 等量负样本"]
    dest = Path(__file__).resolve().parent.parent / "docs" / "bench-worklist.md"
    dest.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"工作单已生成: {dest}")
    print(f"待复核文件≈{total_files}, 告警{total_hits}条")


if __name__ == "__main__":
    main(sys.argv[1:] or LIBS)
