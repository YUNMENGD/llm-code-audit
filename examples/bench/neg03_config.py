"""配置加载（干扰样本：完整防御 = realpath 校验 + safe_load + 类型守卫）。"""
import os
import yaml

BASE = "/etc/app/conf.d"


def load_settings(path: str) -> dict:
    real = os.path.realpath(os.path.join(BASE, path))
    if not real.startswith(BASE + os.sep):
        raise ValueError("path escapes config dir")
    with open(real, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}
