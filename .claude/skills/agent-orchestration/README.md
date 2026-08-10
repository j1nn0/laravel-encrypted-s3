# agent-orchestration

A Claude Code skill for coordinating software engineering work through Herdr with three fixed roles:

- Claude Code / Opus 5 / `thinking: high` — orchestrator and reviewer
- OMP / `opencode-go/deepseek-v4-flash` / `thinking: xhigh` — investigation and research
- Codex / `gpt-5.6-luna` / `effort: max` — implementation

The skill intentionally contains orchestration policy only. Herdr command syntax and terminal control remain the responsibility of the existing `herdr` skill.

## Recommended layout

When both delegated agents are active, the skill prefers Claude Code in the left 50% of the current tab, with OMP in the upper-right 25% and Codex in the lower-right 25%. The ratio is a preference; existing user panes and readability take precedence.

