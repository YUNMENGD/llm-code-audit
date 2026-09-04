"""备份任务（含 1 处缺陷：命令注入；其余代码干净）。"""
import os


def backup(target_dir):
    # EXPECT: CWE-78
    rc = os.system("tar czf /tmp/backup.tgz " + target_dir)
    return rc == 0
