# -*- coding: utf-8 -*-
"""LLM 定级对照实验（论文第3章核心表格）。

设计：
  A 组 = 纯静态基线（治理链全开后的 precision，已有）
  B 组 = 静态网 + LLM 逐条定级（retain/kill）后的 precision
  红线 = LLM 误杀真缺陷（lost_T）——B 组哪怕 precision 再高，杀 T 即失败

  只定级 R-SEC-*/R-LOG-* 静态命中（TODO/风格类无判定价值，浪费调用）。
  每条约 2.5K 输入 + 100 输出 token；五库合计 ~30 条 → 预估 8 万 token 内。
  接 D17 缓存：同 prompt 重放零成本，改参数重跑不重复计费。

用法：
  python tools/ai_adjudicate.py --dry-run     只跑第 1 条，验证链路和单价
  python tools/ai_adjudicate.py               全量跑（跑前打印预估）
  python tools/ai_adjudicate.py --only click  单库
产物：
  out/ai_adjudication.json（逐条明细+聚合）
  控制台摘要；随后人工转 docs/ai-adjudication-results.md
"""
from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codeaudit import cache as C          # noqa: E402
from codeaudit import rules as RL         # noqa: E402
from codeaudit import paths               # noqa: E402
from codeaudit.llm import LLMClient, extract_json_array  # noqa: E402
from codeaudit.realeval import (_current_hits, _pkg_dir,  # noqa: E402
                                load_gt)

LIBS = ["click", "werkzeug", "flask", "requests", "botocore"]
ADJ_RULES = ("R-SEC-", "R-LOG-")
MODEL = "qwen-plus"

SYSTEM = ("你是资深代码安全审计复核员。静态扫描规则报出一条告警，"
          "你根据代码上下文判断它是否为【该规则语义下的真实问题】。"
          "多数告警在成熟库里可能是误报，但不得因『大项目都这么写』而放松；"
          "判定要基于数据流与威胁模型，不基于猜测。"
          "判定前先核对以下三条事实，建立在违背事实的理由上的判定不成立："
          "① except Exception 不捕获 KeyboardInterrupt/SystemExit（它们是"
          "BaseException 直接子类），评估吞异常危害时不得把这类中断算进去；"
          "② 被协议或标准强制规定的哈希算法（如 HTTP Digest 规定 MD5/SHA1）"
          "不是缺陷，usedforsecurity=False 即非安全用途的官方声明，不得以"
          "算法过旧为由保留或建议升级；"
          "③ 调用方显式传入的配置文件内容与 vendored 第三方兼容代码不属于"
          "不可信攻击输入，除非有不可信数据实际流向 exec/eval，不得判 RCE。"
          "只输出一个 JSON 对象。")

USER_TPL = """# 规则
[{rule_id}] {title}
规则含义：{why}

# 告警位置
文件：{fname}  第 {line} 行
命中代码：{evidence}

# 文件上下文（可能截断）
```python
{context}
```

# 输出（仅 JSON）
{{"real": true/false, "confidence": 0~1, "reason": "≤60字判定依据"}}
"""


def _context_of(pkg: Path, rel: str, line: int, span: int = 22) -> str:
    try:
        lines = (pkg / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(文件不可读)"
    lo, hi = max(0, line - 1 - span), min(len(lines), line + span)
    return "\n".join(lines[lo:hi])[:6500]


def adjudicate(client: LLMClient, rule: dict, fname: str, line: int,
               evidence: str, context: str) -> dict:
    prompt = USER_TPL.format(
        rule_id=rule["id"], title=rule["title"], why=rule.get("why", ""),
        fname=fname, line=line, evidence=evidence[:120], context=context)
    key = C.cache_key(SYSTEM + "\x00" + prompt, client.model)
    hit = C.get(key)
    if hit is None:
        raw = client.chat([{"role": "system", "content": SYSTEM},
                           {"role": "user", "content": prompt}])
        C.put(key, raw, model=client.model)
    else:
        raw = hit
    arr = extract_json_array("[" + raw + "]")
    v = arr[0] if arr and isinstance(arr[0], dict) else {}
    return {"real": bool(v.get("real")), "confidence": v.get("confidence"),
            "reason": str(v.get("reason", ""))[:120],
            "cached": hit is not None}


def collect(lib: str) -> list[dict]:
    gt = load_gt(lib)
    if gt is None:
        raise SystemExit(f"缺 ground truth: bench-real/{lib}.json")
    gmap = {(a["file"], a["line"], a["rule"]): a for a in gt["annotations"]}
    pkg = _pkg_dir(lib)
    rs = {r["id"]: r for r in RL.load_rules()}
    rows = []
    for h in _current_hits(pkg):
        rid = h.rule_id
        if not rid.startswith(ADJ_RULES) and not rid.startswith("DISCOVERED-CWE"):
            continue                    # TODO/风格类不定级（口径写进结果）
        a = gmap.get((h.path, h.line_start, rid))
        rows.append({
            "lib": lib, "file": h.path, "line": h.line_start, "rule": rid,
            "title": rs.get(rid, {}).get("title", rid),
            "why": rs.get(rid, {}).get("why", ""),
            "evidence": h.evidence,
            "gt": a["verdict"] if a else "O",       # O=GT外新增
            "pattern": a.get("pattern", "") if a else "",
        })
    return rows


def main(argv: list[str]) -> int:
    dry = "--dry-run" in argv
    only = None
    if "--only" in argv:
        only = [argv[argv.index("--only") + 1]]
    libs = only or LIBS

    client = LLMClient()
    if not client.available():
        print("需要 .env 配置 LLM_API_KEY")
        return 2
    client.model = MODEL

    rows = [r for lib in libs for r in collect(lib)]
    est_in = sum(len(r["why"]) + len(r["evidence"]) for r in rows) / 400
    print(f"待定级 {len(rows)} 条（{', '.join(libs)}），"
          f"预估输入 ≈{len(rows) * 2.5:.0f}K token，缓存命中则免费")
    if dry:
        rows = rows[:1]
        print("dry-run：只跑第 1 条")

    lock = threading.Lock()

    def work(r: dict) -> dict:
        ctx = _context_of(_pkg_dir(r["lib"]), r["file"], r["line"])
        try:
            r.update(adjudicate(client, {"id": r["rule"], "title": r["title"],
                                         "why": r["why"]},
                                r["file"], r["line"], r["evidence"], ctx))
        except Exception as e:                      # noqa: BLE001
            r["error"] = f"{type(e).__name__}: {e}"
            r["real"] = True                        # 失败保守保留
        with lock:
            print(f"  [{r['lib']}] {r['file']}:{r['line']} {r['rule']} "
                  f"gt={r['gt']} → LLM={'保留' if r['real'] else 'Kill'}"
                  f"{'(缓存)' if r.get('cached') else ''}")
        return r

    if len(rows) > 1:
        with ThreadPoolExecutor(max_workers=4) as pool:
            done = list(pool.map(work, rows))
    else:
        done = [work(rows[0])]
    C.flush()

    # 聚合：B 组 = LLM 保留集；红线 = T 被 Kill
    keep = [r for r in done if r.get("real")]
    def P(rs):
        t = sum(1 for r in rs if r["gt"] == "T")
        f = sum(1 for r in rs if r["gt"] == "F")
        return (t, f, round(t / (t + f), 3) if t + f else None)
    tA, fA, pA = P([r for r in done if r["gt"] in "TF"])
    tB, fB, pB = P(keep)
    lost = [f"{r['lib']}:{r['file']}:{r['line']} {r['rule']}"
            for r in done if r["gt"] == "T" and not r.get("real")]
    saved = [r for r in done if r["gt"] == "F" and not r.get("real")]
    summary = {
        "libs": libs, "n": len(done),
        "A_static": {"T": tA, "F": fA, "precision": pA},
        "B_llm_adjudicated": {"T": tB, "F": fB, "precision": pB,
                              "kept": len(keep)},
        "fp_killed": len(saved), "lost_T": lost,
        "novel_O_kept": sum(1 for r in keep if r["gt"] == "O"),
        "detail": done,
    }
    out = Path("out/ai_adjudication.json")
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    print(f"\nA 纯静态:        T{tA}/F{fA}  P={pA}")
    print(f"B 静态+LLM定级:  T{tB}/F{fB}  P={pB}  (保留{len(keep)})")
    print(f"误报被杀 {len(saved)} | 红线：真缺陷误杀 {len(lost)} {lost or ''}")
    print(f"明细 → {out}")
    return 0 if not lost else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
