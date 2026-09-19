# S5 — Dependabot trailer parsing

**Question (SPEC.md §12):** is the `updated-dependencies` trailer present and
parseable on all 8 real open PRs, including csa-wrangler range updates and
Actions bumps?

**Verdict: PASS — 8/8.** Every open Dependabot PR across both enrolled repos
carries a well-formed `updated-dependencies:` YAML block, terminated by the `...`
end-of-document marker. All 8 also pass the §5.1 authenticity checks: single
commit, authored by `dependabot[bot]`, same-repo head, `dependabot/` branch prefix.

Reproduce with `python3 scripts/s5_probe.py` (no auth needed; both repos are public).
Fixtures are snapshotted in `tests/fixtures/real/` by `scripts/snapshot_fixtures.py`.

The spike nonetheless invalidates five specific claims in the approved spec. None
of them threaten the architecture; all of them change Prepare's parsing contract
or Phase 3's fixture expectations.

---

## F1 — The trailer does not contain `directory`, `from`, or `ecosystem`

§5.2 step 5 says the trailer parses into
`{name, ecosystem, directory, from, to, dependency-type, update-type, group}`.

The trailer actually provides only:

| Field | Always present? |
|---|---|
| `dependency-name` | yes |
| `dependency-version` | yes — **the target only** |
| `dependency-type` | yes |
| `update-type` | **no** — see F2 |
| `dependency-group` | only for grouped updates |

So three of the eight fields must be derived elsewhere:

- **`directory`** ← the path of the manifest the package appears in, from the
  changed-files list. This matters more than it looks: §5.6's supersede match rule
  and §6's floor rules both key on directory, and §2 already notes that the same
  package appears in different directories across PRs.
- **`from`** ← the `-` side of the manifest patch hunk.
- **`ecosystem`** ← the manifest path (`.github/workflows/*.yml` → Actions;
  `requirements*.txt`, `pyproject.toml` → pip).

## F2 — `update-type` is absent on exactly the range updates

Missing on #10, #28 and #29 — all three `>=` floor bumps. Present on the pinned
and Actions bumps (#7, #20, #26, #27).

This is the consequential one. csa-wrangler #29 (`anthropic >=0.116.0 → >=0.121.0`)
is the spec's flagship `ZERO_X_MINOR` → **high** case, and it carries no
`update-type` at all. The floor computation therefore **cannot key on
`update-type`**; it must parse and compare the version pair itself, with
`update-type` used only as a cross-check when present.

## F3 — §2 and §12 are wrong about #10 vs #28

Both claim these bump `boto3` in *different* directories, and §12 relies on that
to provide the negative supersede fixture ("must **not** be flagged as
superseding each other").

Both PRs in fact modify the **same file**, `scripts/requirements.txt`:

```
#10  -boto3>=1.34   +boto3>=1.43.42
#28  -boto3>=1.34   +boto3>=1.43.69
```

Same ecosystem, same directory, same normalized name, and #28's target floor is
strictly higher. Under §5.6 this is a **positive** supersede: **#28 supersedes #10**.

Consequences:
- The planned real negative case does not exist and must be synthesized.
- #10/#28 becomes a real positive fixture for full supersession.

(The `deps(dev)` prefix on #10's title is what appears to have misled the draft;
the title prefix reflects Dependabot's config group, not the directory.)

## F4 — #27 does not include boto3, but #26/#27 overlap on recipe-scrapers

§12 asks: "Confirm in S5 whether #27 includes boto3." **It does not.** #27 is
`pytest` + `recipe-scrapers`.

A different overlap exists instead. Both #26 and #27 bump
`recipe-scrapers 15.11.0 → 15.12.0` in `scripts/requirements.txt`:

| PR | Files | Packages |
|---|---|---|
| #26 | `scripts/requirements.txt` | recipe-scrapers → 15.12.0 |
| #27 | `requirements-dev.txt`, `scripts/requirements.txt` | pytest → 9.1.1, recipe-scrapers → 15.12.0 |

Same directory, same package, **equal** target versions. §5.6's tie-break
("if the targets are equal, the higher PR number wins") makes **#27 supersede #26**,
and since recipe-scrapers is all of #26, #26 is *fully* superseded. #27 itself
stays relevant because of pytest.

This is a better real fixture than the one §12 planned — it exercises the
equal-version tie-break, which no synthetic case currently covers.

## F5 — `dependency-version` is unreliable for range updates

csa-wrangler #10's trailer reads `dependency-version: 1.43.34`, while both its
title and its patch say `>=1.43.42`:

```
trailer:  dependency-version: 1.43.34
title:    update boto3 requirement from >=1.34 to >=1.43.42
patch:    +boto3>=1.43.42
```

The patch is authoritative. Since the supersede comparison (§5.6) and the floor
(§6) both turn on the target version, Prepare must take the target from the
**patch**, not from `dependency-version`, at least for range specs.

Relatedly, #10 and #28 both report `dependency-type: direct:production` for a
package in `scripts/requirements.txt` — tooling, not Lambda code. §6's
"minor bump on a `direct:production` dependency → medium" rule would over-rate
these if it trusted the field. The `IMPORT_ONLY_IN_SCRIPTS` concept in §8.1 wants
to key on the manifest path instead.

---

## Proposed spec amendments

1. **§5.2 step 5** — rewrite the trailer contract: the trailer yields name,
   target, type and group; directory, `from` and ecosystem are derived from the
   changed-files list and patches. Target for range specs comes from the patch.
2. **§6** — state that the floor compares parsed version pairs; `update-type` is
   an optional cross-check, never a precondition.
3. **§2** — correct the #10/#28 claim: same directory (`scripts/`), not different.
4. **§12** — replace the supersede fixture table: #28▸#10 (full, higher target)
   and #27▸#26 (full, equal-target tie-break) are real; the negative case must be
   synthesized; #27-includes-boto3 is answered No.
5. **§6 / §8.1** — prefer manifest path over `dependency-type` when deciding
   production-vs-tooling impact.

Nothing here touches the trust boundary, the tier split or the `max(floor, model)`
rule. The changes are confined to Tier 1 parsing and to test expectations.
