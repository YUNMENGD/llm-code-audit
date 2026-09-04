"""凭据注入（干扰样本：常量名含 PASSWORD，存的是环境变量名不是凭据值）。"""
import os

DB_PASSWORD_ENV = "APP_DB_PASSWORD"          # 只是环境变量名
API_KEY_SOURCE = os.environ.get("APP_API_KEY", "")   # 运行时读取，未硬编码


def dsn() -> str:
    return f"postgresql://{API_KEY_SOURCE}@db:5432/app"
