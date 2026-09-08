# -*- coding: utf-8 -*-
"""植入缺陷实验（B）：真实库副本注入已知缺陷 → 测 recall 与定位精度。

为什么需要：bench-real 只能测 precision（成熟库真缺陷无法穷举），
"漏没漏"缺正面回答。植入法（mutation 思路）反着来：答案已知，看抓到几个。

设计：
  · 复制 click / trio / werkzeug 到 ../planted/<lib>/（realtest 原件只读不动）
  · 每库植入 ~10 个缺陷（合计 27），18 条硬规则全覆盖（ENG-002 除外，口径说明）；
    缺陷写成自然功能代码（查询函数/令牌生成等），不是裸 API 堆砌
  · 另植 7 个【陷阱】= 带正确防护的相似写法，期望不报（测治理过度）
  · 评测：与 real-eval 同一引擎同一规则全量扫描 planted/，
    命中窗口 = 植入块行范围（含 ±1），且【定位校验】要求告警行含该缺陷
    特征关键字——抓到但指错行不算满分
  · ENG-002(TODO) 不计入：三库真实 TODO 噪声远大于植入量，会稀释指标
用法：python tools/planted_eval.py            # 幂等：重跑重植入
产物：out/planted_eval.json（检出矩阵），控制台摘要；recall<1 或陷阱破防 → 退出码 1
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codeaudit import rules as RL              # noqa: E402
from codeaudit.realeval import _EXCLUDE        # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REALTEST = ROOT.parent / "realtest"
PLANTED = ROOT.parent / "planted"


def _rmtree(path: Path) -> None:
    """删除（仅限本脚本自产物）：Windows 上 .git pack 文件带只读位。"""
    import os
    import stat

    def _clr(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    shutil.rmtree(path, onerror=_clr)

HEADER = ("\nimport os\nimport sys\nimport pickle\nimport yaml\n"
          "import hashlib\nimport sqlite3\nimport random\nimport string\n"
          "import subprocess\n\n")

# 每条规则的定位关键字：告警行必须包含其一，才算"指向正确代码"
KEYS = {
    "R-SEC-001": ["execute("], "R-SEC-002": ["os.system("],
    "R-SEC-003": ["eval(", "exec("], "R-SEC-004": ["pickle.load", "yaml.load"],
    "R-SEC-005": ["verify=False"], "R-SEC-006": ["=", ],
    "R-SEC-007": ["md5(", "sha1("], "R-SEC-008": ["shell=True"],
    "R-SEC-009": ["random."], "R-SEC-010": ["debug=True"],
    "R-LOG-001": ["except"], "R-LOG-002": ["=[]", "={}"],
    "R-LOG-003": [" is "], "R-ENG-001": ["open(", "connect("],
    "R-STYLE-001": [";"], "R-STYLE-002": ["import *"],
    "R-STYLE-003": ["lambda"],
}

CLICK = [
    ("R-SEC-001", 'def _pl_sqli(cur, user):\n'
                  '    # audit-planted: string-built query\n'
                  '    cur.execute("SELECT * FROM users WHERE name = %s" % user)\n'
                  '    return cur.fetchall()\n'),
    ("R-SEC-002", 'def _pl_oscmd(path):\n    # audit-planted\n'
                  '    return os.system("tar xzf " + path)\n'),
    ("R-SEC-003", 'def _pl_eval(expr):\n    # audit-planted\n'
                  '    return eval(expr)\n'),
    ("R-SEC-004", 'def _pl_pickle_load(f):\n    # audit-planted\n'
                  '    return pickle.load(f)\n'),
    ("R-SEC-005", 'def _pl_noverify(sess, url):\n    # audit-planted\n'
                  '    return sess.get(url, verify=False).text\n'),
    ("R-SEC-006", 'def _pl_hardcode(sess):\n    # audit-planted\n'
                  '    password = "Hunter2!admin"\n'
                  '    return sess.login("root", password)\n'),
    ("R-SEC-007", 'def _pl_md5_pwd(pwd):\n    # audit-planted: password hashing\n'
                  '    return hashlib.md5(pwd.encode()).hexdigest()\n'),
    ("R-SEC-008", 'def _pl_shell(cmd, arg):\n    # audit-planted\n'
                  '    return subprocess.run(cmd + arg, shell=True).returncode\n'),
    ("R-LOG-001", 'def _pl_swallow(fn, *a):\n    # audit-planted: silent except\n'
                  '    try:\n        return fn(*a)\n    except:\n        pass\n'),
    ("R-LOG-002", 'def _pl_mutable(items=[]):\n    # audit-planted\n'
                  '    items.append(1)\n    return items\n'),
    ("R-SEC-010", 'def _pl_debugrun(app):\n    # audit-planted\n'
                  '    app.run(host="0.0.0.0", debug=True)\n'),
    ("TRAP-safe", 'def _pl_trap_param(cur, uid):\n'
                  '    cur.execute("SELECT name FROM t WHERE id = ?", (uid,))\n'
                  '    return cur.fetchone()\n'),
    ("TRAP-listexec", 'def _pl_trap_popen(prog, arg):\n'
                      '    return subprocess.run([prog, arg], shell=False).stdout\n'),
]
TRIO = [
    ("R-SEC-001", 'async def _pl_fmt_sqli(cur, key):\n'
                  '    # audit-planted\n'
                  '    cur.execute("SELECT v FROM kv WHERE k = {}".format(key))\n'),
    ("R-SEC-003", 'async def _pl_exec(code):\n    # audit-planted\n'
                  '    exec(compile(code, "<planted>", "exec"))\n'),
    ("R-SEC-004", 'async def _pl_yaml(blob):\n    # audit-planted: unsafe yaml\n'
                  '    return yaml.load(blob)\n'),
    ("R-SEC-006", 'PLANTED_API_KEY = "sk-liv3-9f8a2c41be7d"\n'),
    ("R-SEC-007", 'async def _pl_sha1(pwd):\n    # audit-planted: secret digest\n'
                  '    return hashlib.sha1(pwd.encode("utf-8")).hexdigest()\n'),
    ("R-LOG-001", 'async def _pl_swallow2(agen):\n    # audit-planted\n'
                  '    try:\n        await agen.aclose()\n'
                  '    except BaseException:\n        pass\n'),
    ("R-LOG-003", 'async def _pl_idcompare(x):\n    # audit-planted\n'
                  '    return x is "planted-token"\n'),
    ("R-ENG-001", 'async def _pl_conn(path):\n    # audit-planted: no with/close\n'
                  '    conn = sqlite3.connect(path)\n'
                  '    return conn.execute("select 1")\n'),
    ("R-STYLE-003", '_pl_lambda = lambda v: v * 2\n'),
    ("TRAP-nosec", 'def _pl_trap_md5(data):  # nosec\n'
                   '    return hashlib.md5(data, usedforsecurity=False).hexdigest()\n'),
    ("TRAP-probe", 'def _pl_trap_probe():\n    # capability detection\n'
                   '    try:\n        return _some_feature()\n'
                   '    except Exception:\n        return False\n'),
]
WERKZEUG = [
    ("R-SEC-002", 'def _pl_wz_cmd(user_path):\n    # audit-planted\n'
                  '    return os.system("convert " + user_path)\n'),
    ("R-SEC-001", 'def _pl_wz_sqli(cur, name):\n    # audit-planted\n'
                  '    cur.execute("SELECT * FROM t WHERE n = %r" % name)\n'),
    ("R-SEC-005", 'def _pl_wz_tls(sess, url):\n    # audit-planted\n'
                  '    return sess.get(url, verify=False).json()\n'),
    ("R-LOG-001", 'def _pl_wz_except(data):\n    # audit-planted\n'
                  '    try:\n        return decode(data)\n'
                  '    except Exception:\n        pass\n'),
    ("R-LOG-002", 'def _pl_wz_default(cache={}):\n    # audit-planted\n'
                  '    cache["hit"] = cache.get("hit", 0) + 1\n    return cache\n'),
    ("R-SEC-009", 'def _pl_wz_token(n=16):\n    # audit-planted\n'
                  '    token_chars = string.hexdigits\n'
                  '    return "".join(random.choice(token_chars) for _ in range(n))\n'),
    ("R-STYLE-001", 'def _pl_wz_semi(x):\n    y = x + 1; return y\n'),
    ("R-LOG-003", 'def _pl_wz_is(x):\n    # audit-planted\n    return x is 42\n'),
    ("R-STYLE-002", 'from .sansio.response import *\n'),
    ("TRAP-realpath", 'def _pl_trap_open(root, rel):\n'
                      '    p = os.path.realpath(os.path.join(root, rel))\n'
                      '    if not p.startswith(os.path.realpath(root)):\n'
                      '        raise ValueError("escape")\n'
                      '    with open(p) as f:\n        return f.read()\n'),
    ("TRAP-reraise", 'def _pl_trap_cleanup(res):\n'
                     '    try:\n        res.commit()\n'
                     '    except Exception:\n        res.rollback()\n        raise\n'),
]
LIBS = {"click": CLICK, "trio": TRIO, "werkzeug": WERKZEUG}
TARGET = {"click": "formatting.py", "trio": "_dtls.py",
          "werkzeug": "urls.py"}


def implant(lib: str, blocks: list[tuple[str, str]]) -> list[dict]:
    """复制整库 → 目标文件末尾追加缺陷块 → 返回带行号清单（块首行）。"""
    src_root = REALTEST / lib
    dst_root = PLANTED / lib
    if dst_root.exists():
        _rmtree(dst_root)
    shutil.copytree(src_root, dst_root,
                    ignore=shutil.ignore_patterns("tests", "docs", "examples",
                                                  "*.egg-info", "__pycache__",
                                                  "tox.ini", "conftest.py",
                                                  ".git", ".github", ".tox"))
    sub = "src" if (dst_root / "src").exists() else lib
    tdir = dst_root / sub / lib
    target = next(tdir.rglob(TARGET[lib]))
    blob = target.read_text(encoding="utf-8") + HEADER
    anchors: list[tuple[str, str, int]] = []  # (expect, 锚点行, 块行数)
    for expect, code in blocks:
        code_lines = [ln for ln in code.splitlines() if ln.strip()]
        blob += "\n\n\n" + code               # 3 空行隔离，防相邻块告警串染
        anchors.append((expect, code_lines[0].strip(), len(code_lines)))
    target.write_text(blob, encoding="utf-8")
    # 锚点行精确定位（要求全文件唯一）
    lines = blob.splitlines()
    manifest = []
    for expect, anchor, nlines in anchors:
        pos = [i + 1 for i, ln in enumerate(lines) if ln.strip() == anchor]
        assert len(pos) == 1, f"锚点不唯一: {anchor!r} -> {pos}"
        manifest.append({"lib": lib, "file": target.name, "start": pos[0],
                         "end": pos[0] + nlines - 1, "expect": expect})
    return manifest


def scan_planted(lib: str) -> list[tuple[str, int, str, str]]:
    sub = "src" if (PLANTED / lib / "src").exists() else lib
    pkg = PLANTED / lib / sub / lib
    rs = RL.load_rules()
    out = []
    for f in sorted(pkg.rglob("*.py")):
        parts = {p.lower() for p in f.resolve().parts}
        if _EXCLUDE & parts or f.name.startswith(("test_", "tests_")):
            continue
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for h in RL.scan_source(src, rs, f.name):
            out.append((f.name, h.line_start, h.rule_id, h.evidence))
    return out


def main() -> int:
    if PLANTED.exists():
        _rmtree(PLANTED)
    manifest = [m for lib, blocks in LIBS.items() for m in implant(lib, blocks)]
    hits = {lib: scan_planted(lib) for lib in LIBS}

    detail = []
    for m in manifest:
        exp, f = m["expect"], m["file"]
        pad = 0 if exp.startswith("TRAP") else 1
        near = [(l, r, ev) for (fn, l, r, ev) in hits[m["lib"]]
                if fn == f and m["start"] - pad <= l <= m["end"] + pad]
        if exp.startswith("TRAP"):
            breach = [r for _, r, _ in near]
            detail.append({**m, "result": "trap_clean" if not breach
                           else "TRAP_BREACH", "alerts": breach})
            continue
        matched = [(l, ev) for l, r, ev in near if r == exp]
        located = any(any(k in ev for k in KEYS.get(exp, [])) for _, ev in matched)
        detail.append({**m,
                       "result": "hit_located" if located else
                                 ("hit_unlocated" if matched else "MISS"),
                       "alerts": [r for _, r, _ in near]})

    defects = [d for d in detail if not d["expect"].startswith("TRAP")]
    traps = [d for d in detail if d["expect"].startswith("TRAP")]
    hit_n = sum(1 for d in defects if d["result"].startswith("hit"))
    loc_n = sum(1 for d in defects if d["result"] == "hit_located")
    miss = [d for d in defects if d["result"] == "MISS"]
    breach = [d for d in traps if d["result"] == "TRAP_BREACH"]

    agg: dict[str, dict] = {}
    for d in defects:
        a = agg.setdefault(d["expect"], {"n": 0, "hit": 0})
        a["n"] += 1
        a["hit"] += d["result"].startswith("hit")

    print(f"植入缺陷 {len(defects)}（18规则全覆盖，ENG-002除外） "
          f"| 抓到 {hit_n} | recall = {hit_n/len(defects):.3f} "
          f"| 定位精确 {loc_n}")
    for e, a in sorted(agg.items()):
        flag = "" if a["hit"] == a["n"] else "   ← MISS"
        print(f"  {e:12s} {a['hit']}/{a['n']}{flag}")
    print(f"防护陷阱 {len(traps)} | 豁免完好 {len(traps)-len(breach)} "
          f"| 破防 {len(breach)}")
    for d in miss:
        print("  漏检:", d["lib"], d["file"], d["start"], d["expect"],
              "块内告警:", d["alerts"])
    for d in breach:
        print("  破防:", d["lib"], d["file"], d["start"], d["expect"],
              "误报:", d["alerts"])
    out = ROOT / "out" / "planted_eval.json"
    out.write_text(json.dumps({"recall": round(hit_n / len(defects), 4),
                               "located": round(loc_n / len(defects), 4),
                               "defects": len(defects), "hits": hit_n,
                               "traps": len(traps), "breach": len(breach),
                               "per_rule": agg, "detail": detail},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"明细 → {out}")
    return 0 if not miss and not breach else 1


if __name__ == "__main__":
    raise SystemExit(main())
