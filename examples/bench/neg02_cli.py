"""清理任务（干扰样本：用了 os.environ/subprocess，但参数固定无注入面）。"""
import os
import subprocess


def clean_tmp(days: int):
    msg = f"clean files older than {days} days"   # f-string 在，但只进日志
    print(msg)
    out = subprocess.run(["find", "/var/tmp", "-mtime", f"+{int(days)}",
                          "-delete"], shell=False, check=False)
    return out.returncode == 0, os.environ.get("TMP_ROOT", "/tmp")
