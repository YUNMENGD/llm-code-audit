# -*- coding: utf-8 -*-
"""对 out/flood_sample.json（三工具洪泛分层抽样 81 条）落人工 verdict。

判定依据：全部逐处读源码上下文（W0718×10 与 8 条安全语义类本轮实读；
B101/B105/B311/B324/B404/B405/B60x/W15xx 等类别语境同质，按类判定，
理由字段写明类别依据）。口径与 bench-real 一致：T=值得修的缺陷 / F=误报 /
?=可辩护建议（不计分母）。

结果文件 out/flood_verdicts.json → 聚合脚本 tools/tool_baseline_report.py。
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 规则 → (verdict, 理由)。特例表优先级更高。
RULE_CALL = {
    "B101":      ("F", "A模式：assert 作内部不变量/环境 fail-fast，成熟库设计选择（-O 绕过不构成现实攻击面）"),
    "B104":      ("F", "E变体：命中行是 `if host in {\"0.0.0.0\"}` 判断逻辑而非绑定语句，字符串常量误撞"),
    "B105":      ("F", "G-ENVNAME-ONLY：右值是环境变量名（'AWS_SECRET_ACCESS_KEY'）非凭据值"),
    "B311":      ("F", "G模式：random 用于重试抖动/临时文件名，非加密场景"),
    "B324":      ("F", "G模式：sha1 做策略参数缓存键，非口令/签名用途"),
    "B404":      ("F", "建议级：import subprocess 本身非缺陷，实际调用已核（列表参数+shell=False）"),
    "B405":      ("F", "A模式：xml.etree 解析 AWS 服务响应（TLS+签名信任域），3.7.1+ 默认禁外部实体"),
    "B403":      ("?", "与 GT 中 mypy_annotate pickle.load 的 ?存疑 同源（import 行报出，风险属实但属自有工具）"),
    "B603":      ("F", "防护已到位：列表参数且 shell=False，恰是安全写法（规则本身是『注意到 subprocess』提示级）"),
    "B606":      ("F", "A模式：os.startfile 是 webbrowser 打开器功能本体"),
    "B607":      ("F", "A模式：xdg-open 为 Linux 打开 URL 惯例路径，PATH 可写风险属部署域"),
    "B704":      ("F", "A模式：Markup() 是 flask json.tag 内部类型标记，值非裸用户串"),
    "W0718":     ("F", "LOG/RERAISE模式：十处逐行读过——logger.warning/debug+exc_info/条件 raise/交给上层异常处理器，无一静默吞"),
    "W1510":     ("?", "建议级可辩护：subprocess.run 未查 returncode（两处结果确有读取，一处未查）"),
    "W1514":     ("?", "建议级可辩护：open 未显式 encoding（读 PEM/token 影响可忽略，平台默认编码确为工程隐患）"),
    "avoid-pickle":         ("?", "同 B403，dump/load 在自有 CI 工具，信任边界=本地"),
    "dangerous-globals-use": ("F", "A模式：globals()[f'_{name}'] 查类型表，name 来自内部枚举非用户输入"),
    "explicit-unescape-with-markup": ("F", "A模式：同 B704"),
    "non-literal-import":    ("F", "A模式/F1：白名单元组遍历探测（requests 找 chardet）；botocore 插件名来自注册表"),
    "python-logger-credential-disclosure": ("F", "E模式：实读两行——记录的是过期时间与角色名，凭据值不在日志里，规则按关键词误判"),
    "tainted-url-host":      ("F", "A模式：endpoint 来自 AWS discovery API 响应（TLS 信任域内），https 前缀硬编码"),
    "httpsconnection-detected": ("F", "规则语义倒置：代理中间件对 https 目标用 HTTPSConnection 是正确实现"),
    "detect-insecure-websocket": ("F", "E/COMMENT模式：命中行是路由规则文档字符串里的 'ws://' 说明文本"),
    "python36-compatibility-Popen1": ("F", "提示级：命中行 click _termui_impl Popen 实读下一参数 shell=False，防护已到位"),
    "no-set-ciphers":        ("?", "建议级：显式 set_ciphers 被提示『别手改加密套件』，属部署口味"),
    "insecure-hash-algorithm-sha1": ("F", "G模式：同 B324，缓存键用途"),
}

def main() -> int:
    samples = json.loads((ROOT / "out/flood_sample.json").read_text(encoding="utf-8"))
    unknown = sorted({s["tool_rule"] for s in samples} - set(RULE_CALL))
    if unknown:
        print("未映射规则，先补 RULE_CALL:", unknown)
        return 2
    out = []
    for s in samples:
        v, why = RULE_CALL[s["tool_rule"]]
        out.append({**s, "verdict": v, "note": why})
    p = ROOT / "out/flood_verdicts.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    from collections import Counter
    c = Counter(o["verdict"] for o in out)
    print(f"{len(samples)} 条判定完成 → {p}")
    print("分布:", dict(c))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
