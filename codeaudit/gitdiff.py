"""增量审计支撑（D）：git diff → 变更文件集合。

用法：
    changed = git_changed_files(repo_dir, base="HEAD~3")
供 audit_path(only_files=changed) 消费。规则：
  · 只取 .py（引擎当前仅支持 Python 规则层）
  · 排除删除文件（diff-filter=drmc 保留：新增/改/重命名目标/复制，删的不审）
  · 返回绝对路径；非 git 仓库/无 git 时抛 GitUnavailable，调用方决定降级
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class GitUnavailable(RuntimeError):
    pass


def git_changed_files(repo: str | Path, base: str = "HEAD",
                      include_untracked: bool = True) -> set[str]:
    repo = Path(repo).resolve()
    def _git(*args: str) -> str:
        r = subprocess.run(["git", *args], cwd=str(repo),
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            raise GitUnavailable((r.stderr or r.stdout).strip()[:200])
        return r.stdout

    try:
        _git("rev-parse", "--git-dir")
    except (GitUnavailable, FileNotFoundError) as e:
        raise GitUnavailable(f"{repo} 不是 git 仓库或 git 不可用: {e}") from e

    out: set[str] = set()
    names = _git("diff", "--name-only", "--diff-filter=drm", base)
    out |= {l.strip() for l in names.splitlines() if l.strip().endswith(".py")}
    if include_untracked:
        un = _git("ls-files", "--others", "--exclude-standard")
        out |= {l.strip() for l in un.splitlines() if l.strip().endswith(".py")}
    return {str(repo / n) for n in out}
