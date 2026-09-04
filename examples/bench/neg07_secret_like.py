"""凭据注入（干扰样本：代码中只有环境变量名，凭据值全程不经手）。"""
import os

DB_PASSWORD_ENV = "APP_DB_PASSWORD"      # 只是环境变量名，不是凭据值


def connect_kwargs() -> dict:
    """驱动按名自行取密：口令值不进入本模块任何字符串。"""
    return {
        "host": "db.internal",
        "password_env_var": DB_PASSWORD_ENV,
        "sslmode": "require",
    }


def has_app_key() -> bool:
    return bool(os.environ.get("APP_API_KEY"))
