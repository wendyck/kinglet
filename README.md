# kinglet

<img src="docs/assets/kinglet.png" alt="A golden-crowned kinglet wearing a small backpack, perched on a branch" width="140" align="right">

Automated, security-conscious triage of Dependabot pull requests.

Kinglet polls enrolled repos for open Dependabot PRs, reviews each one, and posts
a single sticky comment with a per-package risk matrix plus a `risk:low`,
`risk:medium` or `risk:high` label. **The label is advisory — kinglet never
merges, approves or writes to your code.**

See [SPEC.md](SPEC.md) for the full design.

## How it works

```
EventBridge (6 hours) → Poller ┐
                               ├→ Step Functions: Prepare → Reviewer → Finalize
                               │                  (Tier 1)   (Tier 2)   (Tier 1)
                               └→ one sticky PR comment + one risk:* label
```

The design turns on a two-tier trust boundary:

- **Tier 1** (Lambdas) holds every credential. It mints short-lived GitHub App
  tokens narrowed to one repo and one permission per call, and it computes a
  deterministic risk floor.
- **Tier 2** (an ephemeral Fargate task per PR, running an LLM reviewer) has no
  GitHub credentials and no Secrets Manager access. It reads the repo through a
  jailed read-only MCP server, on a read-only root filesystem, and returns one
  strictly validated JSON object.

  It **does** have outbound network access. The VPC interface endpoints were
  deferred, not rejected (SPEC.md §13 Q1): they cost more than the rest of the
  system combined, and what they would protect is public repository data plus a
  short-lived task role whose worst case is Bedrock cost abuse. That trade makes
  tool denial the primary exfiltration control rather than defence in depth,
  which is why the red-team corpus, the per-day review ceiling and the
  build-time policy gate are load-bearing rather than optional.

Final risk is `max(deterministic floor, model)`. The model can raise risk, never
lower it — so prompt injection in a PR body or upstream changelog cannot talk
kinglet into calling something safe.

## Status

**Live** in AWS `220840683614`/us-west-2. The schedule is **ENABLED** and polls
both enrolled repos every six hours (2026-09-20).

Phases 0–3 are complete: the Tier 1 pipeline, the Tier 2 reviewer container, and
the eval suite (330 unit tests, plus an adversarial corpus of 14 cases — 7 run
live against the model in CI, 7/7 contained). Phase 4 is operating it.

To stop it, see the emergency stops at the top of `docs/RUNBOOK.md`.

See `SPEC.md` §12 for the phase detail and `docs/RUNBOOK.md` for how to run it.

## Layout

| Path | What |
|---|---|
| `template.yaml` | SAM stack (us-west-2) |
| `config/repos.yml` | Enrolled repos, framework and watchlist floor rules |
| `schemas/result.schema.json` | The reviewer's output contract |
| `src/` | Tier 1 Lambdas: poller, prepare, finalize, and shared code |
| `reviewer/` | Tier 2 container image, fixed prompt, skill, fs-readonly MCP server |
| `tests/fixtures/real/` | Snapshots of real Dependabot PRs |
| `tests/fixtures/adversarial/` | Prompt-injection corpus |
| `docs/RUNBOOK.md` | Emergency stops, what each alarm means, deploy procedure |
| `docs/spikes/` | Findings F1–F25 from de-risking, and what they changed |
| `infra/ci-oidc.yaml` | The GitHub Actions eval role (separate stack) |
| `scripts/replay.py` | Replay a real PR through the reviewer locally |
| `scripts/redteam.py` | Run the adversarial corpus against the real model |
