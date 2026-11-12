# -*- coding: utf-8 -*-
"""设置中心：在线读写本地 .env（密钥永不离开本机，接口只回脱敏值）。

设计：
- snapshot() 给前端渲染表单：非敏感项回显原值，敏感项只回掩码；
- save() 只改传入的键：敏感项留空/回传掩码 = 保持不变，杜绝误清空；
- 写盘用临时文件原子替换，避免半截 .env；apply=True 时同步 os.environ，
  LLMClient 每次实例化读环境变量，改完即生效，无需重启服务。
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .paths import ROOT

ENV_FILE = ROOT / ".env"

# 键 -> (界面标签, 是否敏感, 默认值)
FIELDS: dict[str, tuple[str, bool, str]] = {
    "LLM_API_KEY": ("主模型密钥", True, ""),
    "LLM_BASE_URL": ("主模型端点", False,
                     "https://dashscope.aliyuncs.com/compatible-mode/v1"),
    "LLM_MODEL": ("主模型名称", False, "qwen-plus"),
    "LLM2_API_KEY": ("交叉复核密钥", True, ""),
    "LLM2_BASE_URL": ("交叉复核端点", False, "https://api.deepseek.com"),
    "LLM2_MODEL": ("交叉复核模型", False, ""),
    "EMBEDDING_BASE_URL": ("向量端点（可选，聊天商无 embeddings 时单独指定）", False, ""),
    "EMBEDDING_API_KEY": ("向量密钥（可选）", True, ""),
    "EMBEDDING_MODEL": ("向量模型", False, "text-embedding-v3"),
    "AUDIT_TEMPERATURE": ("采样温度（0~2）", False, "0.1"),
    "AUDIT_MAX_RETRY": ("调用重试次数（1~10）", False, "3"),
    "AUDIT_CONSISTENCY_RUNS": ("一致性轮数（1~5）", False, "1"),
    "AUDIT_CROSS_REVIEW": ("默认启用交叉复核（0/1）", False, "0"),
}


def read_env_file(path: Path | None = None) -> dict[str, str]:
    """解析 .env 的 KEY=VALUE 行（忽略注释与空行，不做变量展开）。"""
    p = Path(path) if path else ENV_FILE
    out: dict[str, str] = {}
    if not p.exists():
        return out
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", ln.strip())
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 12:
        return "已配置"
    return value[:6] + "…" + value[-4:]


def snapshot() -> dict[str, dict]:
    file_vals = read_env_file()
    out: dict[str, dict] = {}
    for k, (label, secret, _default) in FIELDS.items():
        raw = os.getenv(k, "") or file_vals.get(k, "")
        out[k] = {"label": label, "secret": secret,
                  "configured": bool(raw),
                  "value": mask(raw) if secret else raw}
    return out


def _validate(k: str, v: str) -> None:
    if k == "AUDIT_TEMPERATURE":
        try:
            f = float(v)
        except ValueError:
            raise ValueError("温度必须是数字")
        if not 0 <= f <= 2:
            raise ValueError("温度需在 0~2 之间")
    elif k in ("AUDIT_MAX_RETRY", "AUDIT_CONSISTENCY_RUNS"):
        lo, hi = (1, 10) if k == "AUDIT_MAX_RETRY" else (1, 5)
        try:
            n = int(v)
        except ValueError:
            raise ValueError(f"{FIELDS[k][0]}必须是整数")
        if not lo <= n <= hi:
            raise ValueError(f"{FIELDS[k][0]}需在 {lo}~{hi} 之间")
    elif k == "AUDIT_CROSS_REVIEW":
        if v not in ("0", "1"):
            raise ValueError("交叉复核开关只能是 0 或 1")
    elif k in ("LLM_BASE_URL", "LLM2_BASE_URL", "EMBEDDING_BASE_URL") and v:
        if not v.startswith(("http://", "https://")):
            raise ValueError("端点必须以 http:// 或 https:// 开头")


def save(updates: dict[str, str], env_file: Path | None = None,
         apply: bool = True) -> list[str]:
    """增量更新 .env，返回实际变更的键列表。

    敏感项：空串 / 含省略号 / 等于当前掩码 → 视为「保持不变」跳过。
    env_file/apply 供离线测试注入临时文件，不触碰真实环境。
    """
    target = Path(env_file) if env_file else ENV_FILE
    current = read_env_file(target)
    clean: dict[str, str] = {}
    for k, raw in (updates or {}).items():
        if k not in FIELDS:
            raise ValueError(f"未知设置项：{k}")
        v = str(raw).strip()
        _label, secret, _default = FIELDS[k]
        cur = current.get(k, "")
        if secret and (not v or v == "已配置"
                       or v == mask(cur)
                       or ("…" in v and v == mask(os.getenv(k, "")))):
            continue
        _validate(k, v)
        if v != current.get(k, ""):
            clean[k] = v
    if not clean:
        return []
    lines = (target.read_text(encoding="utf-8").splitlines()
             if target.exists() else [])
    seen: set[str] = set()
    out: list[str] = []
    for ln in lines:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", ln)
        if m and m.group(1) in clean:
            out.append(f"{m.group(1)}={clean[m.group(1)]}")
            seen.add(m.group(1))
        else:
            out.append(ln)
    for k, v in clean.items():
        if k not in seen:
            out.append(f"{k}={v}")
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    tmp.replace(target)
    if apply:
        for k, v in clean.items():
            os.environ[k] = v
    return list(clean)


def test_connection() -> dict:
    """用当前配置发一条最小对话，验证密钥/端点/模型三者匹配。"""
    from .llm import LLMClient
    c = LLMClient()
    if not c.available():
        return {"ok": False, "error": "未配置主模型密钥"}
    try:
        reply = c.chat([{"role": "user", "content": "请只回复两个字：可用"}],
                       temperature=0)
        return {"ok": True, "model": c.model, "reply": reply.strip()[:50]}
    except Exception as e:                        # noqa: BLE001 前端要看到原因
        return {"ok": False, "model": c.model,
                "error": f"{type(e).__name__}: {str(e)[:200]}"}
