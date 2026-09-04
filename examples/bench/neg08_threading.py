"""计数器（干扰样本：threading/global/+= 全出现，但有锁保护无 TOCTOU）。"""
import threading

_lock = threading.Lock()
_total = 0


def bump() -> int:
    global _total
    with _lock:
        _total += 1
        return _total
