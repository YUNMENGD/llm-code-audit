# -*- coding: utf-8 -*-
"""误报反馈聚合升格（G）：queue.json → 候选豁免规则清单（人工确认后手工入知识库）。

原则：机器只攒证据、给候选，**绝不自动改 knowledge/**——与"每条豁免必须有
可复核证据"的项目纪律一致。候选生成条件：
  · 同一 (规则, 文件, 标题) 被标记 ≥ MIN_COUNT 次（默认 2），或
  · 同一规则跨 ≥ MIN_FILES 个文件被反复标记（默认 3）——提示该规则在某类
    语境系统性误报，值得归纳新模式
产物：out/feedback_candidates.md（人读）+ stdout 摘要；退出码恒 0。

用法：python tools/promote_feedback.py [--min-count 2] [--min-files 3]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from codeaudit import feedback as FB               # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-count", type=int, default=2)
    ap.add_argument("--min-files", type=int, default=3)
    a = ap.parse_args()

    rows = FB.all_rows()
    if not rows:
        print("反馈队列为空——在桌面端报告里点『标记误报』后再来聚合")
        return 0

    dup = [r for r in rows if r.get("count", 1) >= a.min_count]
    by_rule: dict[str, list[dict]] = {}
    for r in rows:
        by_rule.setdefault(r["rule"], []).append(r)
    cross = {ru: rs for ru, rs in by_rule.items()
             if len({Path(x.get("path") or "").name for x in rs}) >= a.min_files}

    md = ["# 误报反馈聚合：候选豁免规则", "",
          f"队列 {len(rows)} 条（总标记 {sum(r.get('count',1) for r in rows)} 次）"
          f"· 阈值：重复≥{a.min_count} 或 跨文件≥{a.min_files}", ""]
    if not dup and not cross:
        md += ["暂无达到阈值的候选——继续标记积累。", ""]
    for r in sorted(dup, key=lambda x: -x.get("count", 1)):
        md += [f"## 重复标记：{r['rule']}｜{r['title']}",
               f"- 位置：`{r.get('path','?')}:{r.get('line','?')}`",
               f"- 累计 {r['count']} 次（首次 {r.get('first','')} → 最近 {r.get('last','')}）",
               f"- 证据：`{r.get('evidence','')}`",
               "- 建议：核查该处语境是否构成新的豁免模式（A/E/F1/G/RES/…），"
               "成立则写入 knowledge/ 并补 bench-real 标注", ""]
    for ru, rs in sorted(cross.items(), key=lambda kv: -len(kv[1])):
        if ru in {d["rule"] for d in dup}:
            pass
        files = sorted({Path(x.get('path') or '?').name for x in rs})
        md += [f"## 跨文件系统性：{ru}（{len(files)} 个文件）",
               "- 文件：" + "、".join(f"`{f}`" for f in files[:15]),
               "- 建议：该规则在多种语境反复误报，优先复核 pattern 边界或补 not_when",
               ""]
    out = Path("out/feedback_candidates.md")
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(md), encoding="utf-8")
    print(f"候选 {len(dup)} 条重复标记 + {len(cross)} 个跨文件规则 → {out}")
    print("提示：候选只是建议，写入知识库前须经 bench-real 回测（防误杀）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
