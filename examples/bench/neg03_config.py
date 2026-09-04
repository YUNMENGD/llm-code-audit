"""配置加载（干扰样本：yaml 同名操作但已 safe_load 且来源可信）。"""
import yaml


def load_settings(path: str):
    # 固定本地路径、SafeLoader，非不可信输入
    with open(path) as f:
        return yaml.safe_load(f)
