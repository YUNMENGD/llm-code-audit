"""计数器（干扰样本：threading 特征出现，但封装为类且全程持锁）。"""
import threading


class Counter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total = 0

    def bump(self) -> int:
        with self._lock:
            self._total += 1
            return self._total
