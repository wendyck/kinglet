# kinglet 🐦

Automated, security-conscious triage of Dependabot pull requests.

Kinglet polls enrolled repos for open Dependabot PRs, reviews each one, and posts
a single sticky comment with a per-package risk matrix plus a `risk:low`,
`risk:medium` or `risk:high` label. **The label is advisory — kinglet never
merges, approves or writes to your code.**

See [SPEC.md](SPEC.md) for the full design.

## How it works

```
EventBridge (10 min) → Poller ─┐
                               ├→ Step Functions: Prepare → Reviewer → Finalize
                               │                  (Tier 1)   (Tier 2)   (Tier 1)
                               └→ one sticky PR comment + one risk:* label
```

The design turns on a two-tier trust boundary:

- **Tier 1** (Lambdas) holds every credential. It mints short-lived GitHub App
  tokens narrowed to one repo and one permission per call, and it computes a
  deterministic risk floor.
- **Tier 2** (an ephemeral Fargate task per PR, running an LLM reviewer) has no
  GitHub credentials, no Secrets Manager access and **no route to the internet**.
  It reads the repo through a jailed read-only MCP server and returns one strictly
  validated JSON object.

Final risk is `max(deterministic floor, model)`. The model can raise risk, never
lower it — so prompt injection in a PR body or upstream changelog cannot talk
kinglet into calling something safe.

## Status

Phase 0 — de-risking spikes. Nothing is deployed yet. See SPEC.md §12.

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
