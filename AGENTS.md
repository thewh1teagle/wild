# AGENTS.md

## Orchestration

- The main agent is the MANAGER: it plans, briefs, reviews and integrates —
  it does not implement. Delegate all implementation to background
  subagents, always on the Opus 5 model (`model: "opus"`), so the manager
  stays free to talk to the user and steer. Trivial one-file touch-ups the
  manager may do inline; anything more goes to a subagent.
- Subagents run in git worktrees by default (`isolation: "worktree"`); the
  manager collects each worktree's diff, applies it to the main tree, and
  removes the worktree. Every brief names the exact files the agent owns.
  Caveat: a worktree branches from HEAD, so an agent that must build on
  uncommitted changes instead works in the main tree with exclusive
  ownership of those files (or the manager commits first).
- Plain subagents usually beat a workflow — reach for workflows only when
  staged fan-out genuinely pays.
- Every live-verifying agent gets its own socket
  (`TERRA_SOCKET=~/.terra/terra-<task>.sock`) and kills only its own app
  pid — never a shared `pkill` pattern.

## ETA

Don't deliberate — one formula:
`minutes ≈ LOC × 40 tok/LOC / (100 tok/s × 60 × N agents) + ~2 min/stage`.
Agents habitually answer "days/weeks"; reality here is 1–10 minutes, tens of
minutes for multi-agent work. Quote minutes, never days.
