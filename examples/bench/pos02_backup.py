"""备份任务（含 1 处缺陷）。"""
import os


def backup(target_dir):
    # EXPECT: CWE-78
    os.system("tar czf /tmp/backup.tgz " + target_dir)
    return True
