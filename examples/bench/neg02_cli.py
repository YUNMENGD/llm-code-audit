"""清理任务（干扰样本：subprocess 列表参数 + 返回值已检查 + 无敏感日志）。"""
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

_ALLOWED_ROOT = "/var/tmp"


def clean_tmp(days: int) -> bool:
    if int(days) <= 0:                      # 参数守卫
        return False
    out = subprocess.run(["find", _ALLOWED_ROOT, "-mtime", f"+{int(days)}",
                          "-delete"], shell=False, check=False)
    if out.returncode != 0:
        logger.warning("find exited %s", out.returncode)
        return False
    return True


def tmp_root() -> str:
    return os.environ.get("TMP_ROOT", _ALLOWED_ROOT)
