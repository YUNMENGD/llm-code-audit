"""模板文件下载（含 1 处缺陷）。"""
import os

BASE = "/srv/templates"


def download(name):
    # EXPECT: CWE-22
    path = BASE + "/" + name
    with open(path) as f:
        return f.read()
