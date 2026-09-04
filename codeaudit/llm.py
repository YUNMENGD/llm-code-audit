"""大模型调用封装（OpenAI Chat Completions 兼容协议）。

通义千问 / DeepSeek / GLM / Kimi 均可用，只需改 .env 的 BASE_URL 与 MODEL。
未配置密钥时 available() 返回 False，audit 模块会优雅降级为纯静态规则审计。
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from dotenv import load_dotenv

load_dotenv()


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, model: str | None = None):
        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.base_url = (os.getenv("LLM_BASE_URL",
                       "https://dashscope.aliyuncs.com/compatible-mode/v1")).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "qwen-plus")
        self.max_retry = int(os.getenv("AUDIT_MAX_RETRY", "3"))

    def available(self) -> bool:
        return bool(self.api_key and not self.api_key.startswith("sk-your"))

    def embed(self, texts: list[str]) -> list[list[float]]:
        """批量向量化（DashScope/OpenAI 兼容 embeddings 端点）。带重试退避。"""
        if not self.available():
            raise LLMError("未配置 LLM_API_KEY，无法生成向量")
        model = os.getenv("EMBEDDING_MODEL", "text-embedding-v3")
        out: list[list[float]] = []
        for i in range(0, len(texts), 8):          # 分批：兼容单次条数上限的服务
            payload = {"model": model, "input": texts[i:i + 8], "encoding_format": "float"}
            last_err: Exception | None = None
            for attempt in range(self.max_retry):
                try:
                    out.extend(self._post_embeddings(payload))
                    break
                except (urllib.error.URLError, LLMError, TimeoutError) as e:
                    last_err = e
                    time.sleep(2 ** attempt)
            else:
                raise LLMError(f"向量化失败（重试 {self.max_retry} 次）：{last_err}")
        return out

    def _post_embeddings(self, payload: dict) -> list[list[float]]:
        req = urllib.request.Request(
            self.base_url + "/embeddings",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        try:
            items = sorted(data["data"], key=lambda d: d.get("index", 0))
            return [it["embedding"] for it in items]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"embedding 响应格式异常：{str(data)[:300]}") from e

    def chat(self, messages: list[dict], temperature: float | None = None) -> str:
        """一次对话调用，带重试与指数退避。"""
        if not self.available():
            raise LLMError("未配置 LLM_API_KEY：请复制 .env.example 为 .env 并填入密钥")
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature if temperature is not None
            else float(os.getenv("AUDIT_TEMPERATURE", "0.1")),
        }
        last_err: Exception | None = None
        for attempt in range(self.max_retry):
            try:
                return self._post(payload)
            except (urllib.error.URLError, LLMError, TimeoutError) as e:
                last_err = e
                time.sleep(2 ** attempt)          # 1s, 2s, 4s
        raise LLMError(f"模型调用失败（重试 {self.max_retry} 次）：{last_err}")

    def _post(self, payload: dict) -> str:
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"响应格式异常：{str(data)[:300]}") from e


def extract_json_array(text: str) -> list[dict]:
    """从模型输出里稳健地抠出 JSON 数组（容忍 markdown 围栏与前后废话）。"""
    m = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.S)
    if m:
        text = m.group(1)
    start = text.find("[")
    if start < 0:
        return []
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(text[start:i + 1])
                    return parsed if isinstance(parsed, list) else []
                except json.JSONDecodeError:
                    return []
    return []
