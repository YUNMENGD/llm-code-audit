"""用户配置加载（含 1 处缺陷）。"""
import yaml


def load_settings(raw_text):
    # EXPECT: CWE-502
    return yaml.load(raw_text)
