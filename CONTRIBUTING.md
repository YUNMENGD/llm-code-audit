# 协作规范

## 分支与合并

- `main` 为受保护主分支，只接受 PR 合并，禁止直接 push。
- 功能分支命名：`feature/模块名-简述`，如 `feature/knowledge-cwe-seed`。
- 文档分支命名：`docs/简述`。
- 每个 PR 至少 1 名非作者成员 review 通过后才能合并。
- 每天开工先 `git pull --rebase origin main`，收工前提交自己当天进度，避免冲突堆积。

## Commit 规范

格式：`模块: 做了什么`，例如：

```
knowledge: 新增 SQL 注入 CWE-89 条目 3 条
audit: 函数级 Prompt 增加 few-shot 示例
docs: 更新接口设计文档
```

## 安全红线

- **任何密钥、API Key、`.env` 文件严禁提交**。提交前确认 `git status` 里没有 `.env`。
- 审计测试只用开源/自写代码，不要上传他人闭源项目。

## 验证要求

- 改代码后必须跑 `python tests/test_offline.py` 全绿再提 PR。
- 知识库新增条目必须带 `source` 字段（CWE 编号 / OWASP / 官方文档链接）。

## 进度心跳

每天在对应任务 Issue 下评论一句话进度（做了什么/卡在哪），负责人每日汇总。
