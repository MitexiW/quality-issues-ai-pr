"""AIDev 数据集表定义。详见 https://huggingface.co/datasets/hao-li/AIDev"""

HF_DATASET = "hao-li/AIDev"

# 全量表（~93 万 PR）
FULL_TABLES = {
    "all_pull_request": "PR 元数据（id, title, body, agent, state, timestamps）",
    "all_repository": "仓库元数据（license, language, stars, forks）",
    "all_user": "用户基本信息（id, login, created_at）",
}

# AIDev-pop 子集（stars > 100，含 patch / review 等丰富字段）
POP_TABLES = {
    "pull_request": "PR 元数据（33,596 条）",
    "repository": "仓库元数据（2,807 个）",
    "user": "用户信息",
    "pr_timeline": "PR 事件时间线",
    "pr_comments": "PR 评论",
    "pr_reviews": "PR review",
    "pr_review_comments_v2": "行内 review 评论（推荐，v1 不完整）",
    "pr_commits": "commit 元数据",
    "pr_commit_details": "文件级 diff / patch",
    "pr_task_type": "PR 任务类型（Conventional Commit 分类）",
    "issue": "关联 issue",
    "related_issue": "PR-issue 映射",
}

HUMAN_TABLES = {
    "human_pull_request": "人类 PR 对照组（stars > 500 仓库采样）",
    "human_pr_task_type": "人类 PR 任务类型",
}

TABLES = {**FULL_TABLES, **POP_TABLES, **HUMAN_TABLES}

# 常用 join key
JOIN_KEYS = {
    "pull_request": "id",
    "pr_commit_details": "pr_id",
    "pr_commits": "pr_id",
    "pr_timeline": "pr_id",
    "pr_comments": "pr_id",
    "pr_reviews": "pr_id",
    "pr_review_comments_v2": "pr_id",
    "pr_task_type": "pr_id",
    "related_issue": "pr_id",
    "repository": "id",  # repo_id in pull_request
}
