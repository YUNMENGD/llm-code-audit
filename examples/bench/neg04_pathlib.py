"""模板渲染（干扰样本：路径拼接但已 realpath 校验基目录）。"""
import os

BASE = "/srv/templates"


def download(name: str) -> str:
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE + os.sep):
        raise ValueError("invalid template name")
    with open(path) as f:
        return f.read()
