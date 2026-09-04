"""用户管理服务 —— 故意包含多类典型缺陷的测试样例（仅用于审计系统测试！）。

包含: SQL注入(CWE-89) / 命令注入(CWE-78) / 硬编码密钥(CWE-798) / 不安全反序列化(CWE-502)
     / 裸except / 可变默认参数 / MD5口令哈希 / 路径遍历(CWE-22) / eval / 资源泄漏
"""
import hashlib
import json
import os
import pickle
import sqlite3

DB_PASSWORD = "admin@123456"          # R-SEC-006 硬编码凭据
API_SECRET = "sk-live-9f8e7d6c5b4a"   # R-SEC-006 硬编码凭据


def get_user(user_id):
    conn = sqlite3.connect("users.db")                       # R-ENG-001 未用 with
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")  # R-SEC-001 SQL 注入
    row = cur.fetchone()
    conn.close()
    return row


def export_report(username):
    os.system("tar czf " + username + ".tar.gz /data/reports")  # R-SEC-002 命令注入
    return True


def load_profile(blob):
    data = pickle.loads(blob)                                # R-SEC-004 反序列化
    return data


def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()             # R-SEC-007 弱哈希


def read_config(name):
    path = "/etc/app/" + name                                # CWE-22 路径遍历线索
    try:
        return open(path).read()                             # R-ENG-001 资源泄漏
    except:                                                    # R-LOG-001 裸 except
        return None


def add_tag(item, tags=[]):                                   # R-LOG-002 可变默认参数
    tags.append("new")
    item["tags"] = tags
    return item


def calc(expr):
    return eval(expr)                                         # R-SEC-003 eval


def find_max(nums):
    mx = nums[0]                                              # LOG-001 空列表边界
    for i in range(1, len(nums) + 1):                         # LOG-008 off-by-one
        if nums[i] > mx:
            mx = nums[i]
    return mx
