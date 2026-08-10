# agent-orchestration

A Claude Code skill for coordinating software engineering work through Herdr with three fixed roles:

- Claude Code / Opus 5 / `thinking: high` — orchestrator and reviewer
- OMP / `opencode-go/deepseek-v4-flash` / `thinking: xhigh` — investigation and research
- Codex / `gpt-5.6-luna` / `effort: max` — implementation

The skill intentionally contains orchestration policy only. Herdr command syntax and terminal control remain the responsibility of the existing `herdr` skill.
