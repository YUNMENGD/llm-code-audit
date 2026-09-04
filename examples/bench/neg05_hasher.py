"""文件去重缓存（干扰样本：md5 但不涉口令/签名用途）。"""
import hashlib


def cache_key(data: bytes) -> str:
    # 非安全场景：内容寻址缓存键，MD5 可接受（豁免方式与 bandit 一致）
    return hashlib.md5(data).hexdigest()  # nosec B324
