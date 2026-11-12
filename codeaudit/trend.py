# -*- coding: utf-8 -*-
"""审计历史趋势聚合：把多次审计汇成「项目安全健康度」时间序列。

用途：增量审计 + 回归闭环的看板视图——同一目标多次审计的问题数/严重度
随时间变化，治理是否见效一眼可见。纯聚合历史存档，不新增采集。
"""
from __future__ import annotations

from collections import defaultdict

from . import history as HS

_SEVS = ("critical", "high", "medium", "low")


def aggregate(limit: int = 200, target: str | None = None) -> dict:
    """按时间正序返回趋势点；target 非空时只统计该目标（按路径尾段匹配）。"""
    rows = HS.list_history(limit)
    if target:
        t = target.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        rows = [r for r in rows
                if r.get("target", "").replace("\\", "/").rstrip("/")
                .rsplit("/", 1)[-1] == t]
    rows = sorted(rows, key=lambda r: (r.get("ts", 0), r.get("time_str", ""),
                                       r.get("id", "")))
    points = []
    for r in rows:
        sv = r.get("by_severity") or {}
        points.append({
            "id": r["id"], "time_str": r.get("time_str", ""),
            "target": r.get("target", ""), "mode": r.get("mode", ""),
            "total": r.get("total", 0),
            "critical": sv.get("critical", 0), "high": sv.get("high", 0),
            "medium": sv.get("medium", 0), "low": sv.get("low", 0),
        })
    totals = [p["total"] for p in points]
    summary = {
        "runs": len(points),
        "first_total": totals[0] if totals else 0,
        "last_total": totals[-1] if totals else 0,
        "delta": (totals[-1] - totals[0]) if totals else 0,
        "max_total": max(totals) if totals else 0,
        "targets": sorted({p["target"] for p in points}),
    }
    return {"points": points, "summary": summary}


def render_trend_svg(agg: dict, width: int = 720, height: int = 200) -> str:
    """原生 SVG 迷你趋势图（总问题数折线 + 严重/高危堆叠提示），无 JS 依赖。"""
    pts = agg["points"]
    if not pts:
        return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">'
                '<text x="50%%" y="50%%" text-anchor="middle" fill="#8496b0" '
                'font-size="13">暂无历史数据</text></svg>' % (width, height))
    pad_l, pad_r, pad_t, pad_b = 40, 16, 16, 28
    iw, ih = width - pad_l - pad_r, height - pad_t - pad_b
    mx = max([p["total"] for p in pts] + [1])
    n = len(pts)

    def x(i):
        return pad_l + (iw * i / max(1, n - 1))

    def y(v):
        return pad_t + ih - (ih * v / mx)

    poly = " ".join(f"{x(i):.1f},{y(p['total']):.1f}" for i, p in enumerate(pts))
    crit = " ".join(f"{x(i):.1f},{y(p['critical'] + p['high']):.1f}"
                    for i, p in enumerate(pts))
    grid = "".join(
        f'<line x1="{pad_l}" y1="{y(v):.1f}" x2="{width - pad_r}" y2="{y(v):.1f}" '
        f'stroke="#e3ecf7" stroke-width="1"/>'
        f'<text x="{pad_l - 6}" y="{y(v) + 4:.1f}" text-anchor="end" '
        f'fill="#8496b0" font-size="10">{v}</text>'
        for v in {0, mx // 2, mx})
    dots = "".join(
        f'<circle cx="{x(i):.1f}" cy="{y(p["total"]):.1f}" r="3" fill="#3d7fd9"/>'
        for i, p in enumerate(pts))
    labels = ""
    if n > 1:
        labels = (f'<text x="{pad_l}" y="{height - 8}" fill="#8496b0" '
                  f'font-size="10">{pts[0]["time_str"][5:16]}</text>'
                  f'<text x="{width - pad_r}" y="{height - 8}" text-anchor="end" '
                  f'fill="#8496b0" font-size="10">{pts[-1]["time_str"][5:16]}</text>')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="Microsoft YaHei,sans-serif">'
        f'<rect width="{width}" height="{height}" fill="#fff" rx="8"/>'
        f'{grid}'
        f'<polyline points="{crit}" fill="none" stroke="#e08a8a" stroke-width="1.5" '
        f'stroke-dasharray="4 3"/>'
        f'<polyline points="{poly}" fill="none" stroke="#3d7fd9" stroke-width="2"/>'
        f'{dots}{labels}'
        f'<text x="{pad_l}" y="{pad_t - 4}" fill="#5a6b85" font-size="11">'
        f'总问题数（蓝）· 严重+高危（红虚线）</text></svg>')
