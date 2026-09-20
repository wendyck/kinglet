# Security fixtures (SPEC.md §5.7, Phase 3)

The banner on a Kinglet comment comes from the Dependabot **alerts API** and from
nowhere else. PR text saying "SECURITY FIX" must never produce one. These
fixtures pin both halves of that.

| File | Provenance |
|---|---|
| `alerts-none-csa-wrangler.json` | **Recorded** 2026-09-20 from `GET /repos/wendyck/csa-wrangler/dependabot/alerts?state=open`. Genuinely empty — neither enrolled repo has ever had an open alert, at `state=all` either. |
| `alerts-boto3-pip.json` | **Schema-derived, not recorded.** Built from GitHub's documented alert response because no enrolled repo has an alert to capture. Carries the full field set, including the fields `match_alerts` ignores, so the parser is exercised against the real shape rather than against the five keys it happens to read. |

If a real alert ever appears on an enrolled repo, record it and replace
`alerts-boto3-pip.json` — a captured response beats a reconstructed one, and the
tests here are written against the fields, not the file.
