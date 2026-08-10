---
name: agent-orchestration
description: >-
  Orchestrates software engineering tasks with Claude Code as the primary
  orchestrator, OMP for investigation and research, and Codex for
  implementation. Use when a task benefits from multi-agent coordination,
  including feature development, bug fixes, refactoring, static analysis,
  technical research, architecture exploration, or new project work. Uses the
  herdr skill for agent coordination. Do not use for trivial tasks where
  delegation would add more overhead than value.
---

# Agent Orchestration

Use the `herdr` skill for multi-agent coordination.

You are **Claude Code** and remain the primary orchestrator throughout the task.
Do not delegate the orchestrator role, final review, or completion decision to another agent.

## Roles

- **Orchestrator:** Claude Code / Opus 5 / `thinking: high`
- **Investigation:** OMP / `opencode-go/deepseek-v4-flash` / `thinking: xhigh`
- **Implementation:** Codex / `gpt-5.6-luna` / `effort: max`

### Claude Code — Orchestration, Decisions, and Review

You are responsible for:

- understanding and planning the task;
- defining objectives, constraints, scope, and completion criteria;
- deciding whether investigation is necessary;
- evaluating investigation results and validating hypotheses;
- determining implementation strategy and scope;
- delegating implementation;
- reviewing actual changes and verification results;
- deciding whether additional investigation or implementation is necessary;
- making the final completion decision.

### OMP — Investigation and Research

Delegate investigation and analysis to OMP when useful.

OMP is responsible for:

- investigating existing codebases when applicable;
- researching technologies, libraries, frameworks, APIs, specifications, documentation, and implementation approaches;
- identifying root causes, dependencies, constraints, related areas, and potential impact;
- comparing alternatives when technical decisions require evidence;
- providing hypotheses with supporting evidence;
- collecting information necessary for planning and implementation decisions.

Investigation is not limited to existing codebases. For new projects or tasks without an existing implementation, use OMP for relevant technical research and analysis when it improves the implementation decision.

### Codex — Implementation

Delegate implementation to Codex by default.

Codex is responsible for:

- implementing features and fixes;
- creating new code and project structures;
- refactoring;
- adding or updating tests;
- updating documentation when necessary;
- reporting the resulting changes and verification results.

## Recommended Herdr Layout

Keep Claude Code visually dominant because it is the primary orchestrator and the place where decisions, review, and completion happen.

When both delegated agents are active, prefer this layout in the current tab:

```text
┌──────────────────────────────┬──────────────────────┐
│                              │                      │
│                              │         OMP          │
│                              │   Investigation      │
│                              │       ~25%           │
│        Claude Code           ├──────────────────────┤
│        Orchestrator          │                      │
│           ~50%               │        Codex         │
│                              │   Implementation     │
│                              │       ~25%           │
└──────────────────────────────┴──────────────────────┘
```

Layout policy:

- Keep Claude Code in the left half of the tab whenever practical.
- Use the right half as the delegated-agent area.
- Place OMP in the upper-right pane and Codex in the lower-right pane when both are active.
- If only one delegated agent is active, it may use the entire right half.
- When adding the second delegated agent, split the existing right-side agent area into upper and lower panes instead of splitting Claude Code's pane again.
- Keep focus on Claude Code for background delegation unless the user explicitly asks to focus another pane.
- Preserve the current working directory for delegated panes unless the task requires a different location.
- Reuse suitable existing agent panes when practical instead of creating unnecessary panes.
- Treat the 50% / 25% / 25% ratio as a preferred target, not a requirement that justifies making panes unreadable.
- Do not rearrange, move, resize, or close user-owned panes merely to force this layout. If the current tab cannot accommodate it cleanly, use the closest readable layout and preserve the user's existing workspace.
- Do not create a new workspace, tab, or worktree solely to achieve this layout unless the user explicitly requests it.

Use the `herdr` skill as the authority for the actual pane inspection, split, focus, and agent-start commands. This skill defines the desired topology, not Herdr CLI syntax.

## Workflow

1. Define the objective, constraints, scope, and completion criteria.
2. Split large tasks into small, reviewable units and make progress incrementally.
3. When investigation is necessary, delegate it to OMP.
4. Evaluate OMP's evidence and hypotheses yourself. Request additional investigation when confidence is insufficient.
5. Determine the implementation strategy, scope, constraints, and completion criteria yourself.
6. Delegate implementation to Codex.
7. Review the actual changes and verification results yourself.
8. If problems remain, decide whether additional investigation or implementation is required.
9. Run appropriate project-specific verification and confirm the completion criteria before declaring the task complete.

Do not pass OMP's investigation directly to Codex as an implementation instruction. You must evaluate the investigation and determine the implementation strategy first.

## Investigation Handoff

Require OMP to report investigation results concisely with:

- conclusion;
- evidence and sources;
- relevant code, files, documentation, APIs, or specifications when applicable;
- constraints and impact;
- alternatives when relevant;
- hypothesis and confidence when applicable.

Avoid unnecessary verbose explanations. Prefer precise references and actionable evidence.

## Implementation Handoff

When delegating to Codex, clearly communicate:

- objective;
- scope;
- constraints;
- implementation strategy;
- completion criteria;
- relevant investigation findings.

Do not over-specify implementation details unless they are necessary constraints. Let Codex make local implementation decisions within the approved strategy and scope.

## Review and Retry Policy

Review implementations for:

- whether the objective and completion criteria are satisfied;
- consistency with the chosen implementation strategy;
- unnecessary or out-of-scope changes;
- unintended impact on existing behavior when applicable;
- verification results;
- whether the root cause is addressed rather than merely bypassed when fixing a problem.

If a fix leads to a different problem, treat it as progress when appropriate and continue.

If the same problem recurs after implementation or correction:

1. Do not immediately ask Codex for another local fix.
2. Re-evaluate the failure, assumptions, investigation results, and implementation strategy yourself.
3. If the cause or hypothesis is uncertain, delegate investigation back to OMP.
4. Evaluate the new findings and update the hypothesis and strategy.
5. Only then delegate another implementation to Codex.

Do not repeatedly stack local fixes on the same failure.

If retries produce no meaningful progress, stop repeating the same approach and reconsider the strategy. If a safe and reasonable solution still cannot be determined, summarize the findings and attempts and consult the user.

## Blocked Agents

If an agent becomes `blocked`:

1. determine why it is blocked;
2. inspect the available context or output;
3. refine the instruction, provide missing information, or perform additional investigation;
4. retry only after addressing the cause.

Do not resend the same instruction unchanged.

## Escalation

Ask the user instead of making assumptions when:

- requirements or completion criteria contain significant ambiguity;
- a choice would substantially change behavior or architecture;
- destructive or irreversible operations are required;
- the required change substantially exceeds the requested scope;
- a decision could affect security or important data;
- investigation and retries cannot establish a safe and reasonable approach.

## Operating Rules

- You are Claude Code and remain the primary orchestrator throughout the task.
- Do not delegate orchestration, final review, or the completion decision.
- Delegate investigation and research to OMP when useful.
- Delegate implementation to Codex by default.
- Keep investigation, implementation, and review responsibilities separate.
- Avoid unnecessary delegation; handle trivial checks yourself.
- Keep changes small and reviewable whenever practical.
- Do not repeatedly apply local patches when the same failure persists; reconsider assumptions, hypotheses, and strategy.
- Do not perform destructive or irreversible operations, out-of-scope changes, or unnecessary access to or disclosure of secrets without explicit permission.
- Follow project-specific rules and verification procedures from the project's `CLAUDE.md`; those rules take precedence over generic guidance in this skill.

## Delegation Boundary

Use judgment before delegating. Multi-agent coordination is valuable when investigation, implementation, or independent validation is substantial enough to justify the handoff. Do not invoke OMP or Codex merely to satisfy the workflow when the task is trivial and can be completed safely and efficiently by Claude Code alone.
