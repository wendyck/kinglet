# S1–S4 — OpenClaw spikes

Pinned version under test: **openclaw 2026.9.5** (`ec9c1a1`), installed from npm.
Probe image: `node:24-slim` + `npm i -g openclaw@2026.9.5`.

| Spike | Status |
|---|---|
| S1 — headless agent returns parseable JSON | **blocked** (needs a model; see Blocker) |
| S2 — Bedrock via task-role creds, no internet | **blocked** (see Blocker) |
| S3 — deny posture passes `doctor --lint`; red-team fails | **partial** — `--lint` confirmed to exist; posture unverified |
| S4 — guardrail attachment supported or ruled out | **provisionally ruled out** — see F9 |

---

## Blocker — the Kinglet AWS account is in verification hold

Every `bedrock-runtime:InvokeModel` call in `220840683614` returns:

```
AccessDeniedException: Your account is currently being verified. Verification
normally takes less than 2 hours.
```

This is the standard new-account hold, not a misconfiguration: `bedrock:ListInferenceProfiles`
succeeds and shows all the Claude profiles ACTIVE, including
`us.anthropic.claude-sonnet-5`. Nothing to fix — retry after the hold clears.

It blocks S1, S2, and S3's red-team runs, all of which need a live model. The
findings below come from the CLI surface and config schema, which need no model.

---

## F6 — The base image must be Node 24, not "LTS"

§5.3 specifies "pinned `node` LTS slim". `node:22-slim` — currently an LTS line —
**fails at install**:

```
[openclaw] error: this OpenClaw release requires Node >=24.16.0 <25 || >=26.1.0.
[openclaw] detected Node 22.23.2
```

Verified working: `node:24-slim` (Node 24.21.0). Note the ceiling: `<25`. The
upper bound means a bare `node:24-slim` tag is *not* safe to float long-term
either; pin the digest, and treat a Node bump as a deliberate, tested change the
way §13 treats model upgrades.

Related supply-chain note: the global install reports five packages with install
scripts — `openclaw`, `@google/genai`, `koffi`, `tree-sitter-bash`, `protobufjs`.
The image build should set `allow-scripts` to exactly that list rather than
allowing scripts wholesale, so a new script-bearing transitive dependency fails
the build instead of running silently.

## F7 — `agent exec` removes the need for a gateway entirely

§5.3 step 2 starts an OpenClaw gateway on loopback, and §8 then spends five
requirements constraining it (`gateway.bind=loopback`, `gateway.http.denyEndpoints`,
remote mode disabled, and two policy-gate clauses).

`openclaw agent exec` — "Run one isolated headless embedded agent turn" — needs
none of it:

| Flag | Why it matters here |
|---|---|
| `--isolated` | Ignores ambient config, runs against exec defaults only |
| `--config <path>` | Pins a reproducible run against a known config file |
| `--state-dir <dir>` | Explicit state directory |
| `--message-file <path>` | The fixed baked-in prompt, unchanged from §5.3 |
| `--json` | "Stable agent-exec JSON envelope" — exactly what S1 needs |
| `--timeout <seconds>` | Per-run deadline, complementing the task timeout |
| `--model <provider/model>` | Pins the Bedrock model per §13 Q2 |

Dropping the gateway removes a listening socket, an HTTP surface and an auth
token from a container whose entire purpose is to be untrusted. That is a
straightforward security win, and it simplifies §8.

Consequence for §5.3: `--session-key agent:kinglet:pr-<...>` is a *gateway* flag
and does not exist on `agent exec`. The per-PR isolation it provided is already
guaranteed more strongly by a fresh container and a fresh `--state-dir`, so the
session-key convention can be dropped rather than replaced.

## F8 — `workspaceAccess` is nested under `sandbox`

§8 says "Agent `kinglet`: one agent, with `workspaceAccess: none`". The key exists
but not at agent top level. It is:

```
agents.defaults.sandbox.workspaceAccess       : "none" | "ro" | "rw"
agents.entries.<id>.sandbox.workspaceAccess   : same
```

`agents.defaults` itself has no `workspaceAccess`. Write it under `sandbox`.

## F9 — No guardrail attachment in the config schema (S4)

The string `guardrail` does not appear anywhere in `openclaw config schema`
(2.4 MB, all 40 top-level sections). There is no `guardrailIdentifier` and no
`streamProcessingMode`.

So §8's optional "attach the Bedrock Guardrail in the provider config" is
**provisionally ruled out**, and the spec's own fallback governs: Finalize's
`ApplyGuardrail` on the output is authoritative either way (§7.2 step 4), and
Prepare's `ApplyGuardrail` on the input already covers the prompt-attack filter.
No design change needed — S4 resolves to "not supported, fallback applies".

Worth one runtime confirmation once a model is available, since a provider could
in principle read an env var the schema does not describe.

## F10 — Bedrock provider is present; task-role credentials should work

`bedrock` appears 396 times across the installed dist, including the model
registry, so it is a first-class provider rather than a doc mention.

The bundled AWS SDK resolves `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` and
`AWS_CONTAINER_CREDENTIALS_FULL_URI`, which is precisely the ECS task-role
mechanism §9 depends on. It also honors `AWS_BEARER_TOKEN_BEDROCK` and
`AWS_BEDROCK_SKIP_AUTH` — the policy gate should assert **neither** is set in the
reviewer image, since either could route around the task role.

This is a good signal for S2 but not a pass: it has not been executed.

## F11 — `group:` token syntax is unconfirmed

§8 specifies `tools.deny: [group:runtime, group:fs]`. The schema types
`tools.allow`, `tools.deny` and `tools.alsoAllow` as plain `string[]` with no
enum and no pattern, so it neither confirms nor refutes the `group:` prefix.

`tools` does have per-capability sections that may be the intended mechanism
instead: `tools.exec`, `tools.fs`, `tools.web`, `tools.subagents`,
`tools.sessions_spawn`, `tools.elevated`, `tools.github`, `tools.browser`-adjacent
entries, plus `tools.profile` for a baseline posture.

`tools.allow` is documented as an "absolute tool allowlist that replaces
profile-derived defaults for strict environments", which matches §8's intent
(`mcp__fs_readonly__*` only) better than the denylist does. **Prefer the
allowlist as the primary control and keep the denylist as defense in depth**, and
resolve the exact token syntax against `doctor --lint` before writing the policy
gate.

---

## Open questions for the image build

- **Fargate CPU architecture.** The spec does not say. Local Docker is
  `linux/aarch64`; Fargate supports ARM64 and it is cheaper. Choosing ARM64 means
  local builds match the runtime, so this should be decided before the Dockerfile
  is pinned.
- **Node upper bound.** `<25` means Node 25 is excluded outright. Pin by digest.
