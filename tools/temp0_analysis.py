# -*- coding: utf-8 -*-
"""C 实验分析：temperature=0 定级 vs 0.1 各轮的翻转率与稳定性。

输入：out/ai_adjudication.round2.json / round3(=ai_adjudication.json) / t0
输出：控制台对照表（写进 docs 的素材由人工整理，数字以本脚本为准）
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(name: str):
    p = ROOT / "out" / name
    if not p.exists():
        return None
    return {tuple(k.split("|")): v for k, v in
            {(f"{r['lib']}|{r['file']}|{r['line']}|{r['rule']}"): r
             for r in json.loads(p.read_text(encoding="utf-8"))["detail"]}.items()}


def flip(a, b, la, lb):
    common = set(a) & set(b)
    diffs = [(k, a[k].get("real"), b[k].get("real"), a[k]["gt"])
             for k in sorted(common) if a[k].get("real") != b[k].get("real")]
    print(f"{la} vs {lb}: 共同条目 {len(common)}，翻转 {len(diffs)}"
          f"（{len(diffs)/len(common)*100:.1f}%）")
    for k, x, y, gt in diffs:
        print(f"   {k[0]:9s} {k[1]}:{k[2]} gt={gt}  {x} → {y}")
    return diffs


def main() -> None:
    r2 = load("ai_adjudication.round2.json")
    r3 = load("ai_adjudication.json")
    t0 = load("ai_adjudication.t0.json")
    if r2 and r3:
        flip(r2, r3, "round2(t=.1)", "round3(t=.1)")
    if r3 and t0:
        d = flip(r3, t0, "round3(t=.1)", "t0")
    # 红线与精度
    d0 = json.loads((ROOT / "out/ai_adjudication.t0.json").read_text(encoding="utf-8"))
    b = d0["B_llm_adjudicated"]
    print(f"\nt0 汇总: kept={b['kept']} T={b['T']} F={b['F']} P={b['precision']} "
          f"lost_T={len(d0['lost_T'])} fp_killed={d0['fp_killed']}")


if __name__ == "__main__":
    main()
