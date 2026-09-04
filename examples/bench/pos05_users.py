"""会员注册（含 1 处缺陷）。"""
import hashlib


def set_password(user, plain):
    # EXPECT: CWE-327
    user.pwd_hash = hashlib.md5(plain.encode()).hexdigest()
    return user
