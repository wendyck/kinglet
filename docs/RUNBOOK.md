# kinglet runbook

Operational procedures for the Dependabot triage bot. Design rationale lives in
`SPEC.md`; this file is what you want at 2am.

**All commands assume `AWS_PROFILE=kinglet` and `us-west-2`.** If the AWS CLI
returns `Token has expired and refresh failed`, run `aws sso login --profile
kinglet` first — an expired token surfaces as almost any other error, which has
already cost one debugging session.

Commands that need the account ID use `${ACCOUNT_ID}`. Set it once per shell:

```bash
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

---

## 0. Blast radius

Kinglet is **advisory**. It posts one sticky comment and one `risk:*` label per
PR. It never merges, approves, closes, or writes to code. The worst case from a
malfunction is a wrong or missing comment, not a bad merge.

Two facts that bound everything below:

- **Tier 2 holds no credentials.** The reviewer container has no GitHub token,
  no Secrets Manager access, and a read-only filesystem. A compromised reviewer
  can waste Bedrock spend; it cannot post, push, or read a secret.
- **The model cannot lower risk.** Final risk is `max(deterministic floor,
  model)`. A model that says `low` on something the floor calls `high` changes
  nothing.

---

## 1. Emergency stop

In increasing order of disruption. Pick the smallest one that fixes it.

### Stop kinglet starting new reviews — immediately

```bash
aws lambda put-function-concurrency \
  --function-name kinglet-poller \
  --reserved-concurrent-executions 0 --region us-west-2
```

Takes effect in seconds. In-flight executions continue; nothing new starts. The poller runs every six
hours, so in most cases you have time — check when it last ran before assuming
you are racing it.

This **drifts from CloudFormation**, so undo it deliberately:

```bash
aws lambda delete-function-concurrency \
  --function-name kinglet-poller --region us-west-2
```

Expect `kinglet-poller-silent` to fire while it is in place. That is correct —
you stopped it, and the alarm is telling the truth.

### Stop it properly

```bash
# samconfig.toml: ScheduleState=DISABLED
make build && sam deploy
```

Slower (~2 minutes) but leaves no drift. This is the right one if the stop is
going to last more than an hour.

### Fall back to the Phase 1 stub reviewer

If the container is the problem — bad image, Bedrock failure, runaway spend —
route reviews back to the stub without redeploying the pipeline:

```bash
# samconfig.toml: ReviewerEnabled=false
make build && sam deploy
```

Both reviewers stay deployed, so this is a parameter change, not a rebuild.
Prepare reports `reviewer_mode` in its output, so you can confirm which path a
given execution took. Flipping back is the same change in reverse.

### Kill one in-flight execution

```bash
aws stepfunctions list-executions \
  --state-machine-arn arn:aws:states:us-west-2:${ACCOUNT_ID}:stateMachine:kinglet-review \
  --status-filter RUNNING --region us-west-2

aws stepfunctions stop-execution --execution-arn <arn> --region us-west-2
```

A stopped execution does **not** run the §5.8 failure path, so the PR gets no
comment and stays a candidate for the next poll. That is usually what you want.

---

## 2. The alarms

All three publish to `arn:aws:sns:us-west-2:${ACCOUNT_ID}:kinglet-alerts`
(→ `kinglet@wendyk.org`). The two poller alarms also send on recovery.

| Alarm | Fires when | First thing to check |
|---|---|---|
| `kinglet-poller-errors` | A poller run failed | Poller logs. GitHub App credentials and rate limits are the usual causes. Nothing is picked up until the next run in six hours. |
| `kinglet-poller-silent` | No poller invocation in seven hours, schedule `ENABLED` | The EventBridge schedule `kinglet-poll` and the scheduler role. Only exists while the schedule is on. |
| `kinglet-review-failures` | Any review execution failed (15 min) | The failed execution's history, then §5.8 below. |

```bash
aws logs tail /aws/lambda/kinglet-poller --since 1h --region us-west-2
aws logs tail /aws/lambda/kinglet-prepare --since 1h --region us-west-2
aws logs tail /aws/lambda/kinglet-finalize --since 1h --region us-west-2
```

### A review failed (§5.8)

The pipeline catches every state into Finalize in `mode=failure`, so a failed
review is **not** silent: the PR gets a comment saying kinglet could not
complete the review, a `risk:high` label, and a marker with `status=failed` so
the poller does not loop on it.

To retry after fixing the cause:

```bash
scripts/retry.sh wendyck/csa-wrangler 29
```

It deletes the marker comment after confirming, which makes the PR a candidate
again on the next poll — up to six hours away, so do not wait on it. Deliberate by design — the `status=failed` marker exists
precisely to stop automatic retries.

### A budget alarm fired

`kinglet-bedrock-daily` and `kinglet-bedrock-monthly` are **lagging** — AWS cost
data is hours behind, so they report spend that already happened. The real-time
control is `MaxStartsPerDay` (25), enforced in the poller against Step Functions
executions started today. `MaxStartsPerRun` (4) bounds a single poll, so the
practical ceiling is 16 a day across four polls.

Note what that cap does *not* cover: local `replay.py` and `redteam.py` runs go
straight from Docker to Bedrock and start no execution, so they are not capped
by anything. If spend is unexplained, check whether someone was running evals.

---

## 3. Verifying the alert path

**Do this after any change to the topic, the subscription, or the domain's mail
routing.** An alert path is not verified until a notification has been watched
arriving; it spent an entire phase deployed, wired and delivering nothing.

```bash
aws cloudwatch set-alarm-state --alarm-name kinglet-poller-errors \
  --state-value ALARM --state-reason "alert path test" --region us-west-2
```

Then check **both** ends:

```bash
aws cloudwatch describe-alarm-history --alarm-name kinglet-poller-errors \
  --max-items 3 --region us-west-2 \
  --query 'AlarmHistoryItems[].[Timestamp,HistorySummary]' --output text
```

Look for `Successfully executed action` — and then look in the inbox. AWS
reporting success is not evidence of delivery.

### If the mail does not arrive

Go to **Google Workspace Admin → Reporting → Email Log Search** before touching
any mail setting. It shows per-recipient disposition and names the rule that
acted. Everything else is guessing.

Two traps, both of which cost time already:

- **Search for `amazonses.com`, not `sns.amazonaws.com`.** SNS sends through
  SES, so the envelope sender is `...@<region>.amazonses.com`.
  `sns.amazonaws.com` appears only in the `From:` header, so searching for it
  returns nothing and reads as proof the mail was never sent.
- **A `Dropped` disposition is a routing rule, not spam.** `kinglet@` and
  `claude@` are explicit aliases on the `wck@` account for this reason: the
  catch-all routing rule silently discarded mail addressed to non-mailboxes
  after accepting it with `250 OK`.

The approved-senders list "AWS emails" (Gmail → Spam, Phishing and Malware)
holds both domains with authentication required. An address list does nothing
until a spam setting references it.

---

## 4. Deploys

```bash
make test          # 327 unit tests
make lint
make build
sam deploy --no-execute-changeset    # read the changeset FIRST
```

**Always read the changeset.** `sam deploy` pushes the whole template and every
parameter in `samconfig.toml`, not just what you edited. Confirm the resource
list is what you expect, then execute it by ARN.

Parameter values live in `samconfig.toml` because **CloudFormation keeps stored
parameter values** — changing a default in `template.yaml` does not move an
existing stack. That has silently failed once already, leaving a guardrail on v1
after v2 was published.

The reviewer image is separate from the stack:

```bash
make image
docker tag kinglet-reviewer:dev ${ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com/kinglet-reviewer:phase2
# then docker push, and bump ReviewerImageTag if the tag changed
```

---

## 5. Facts worth not re-deriving

| Thing | Value |
|---|---|
| AWS account | `aws sts get-caller-identity`, `us-west-2`, profile `kinglet` |
| GitHub App | `kinglet-bot`, App ID `5003415`, installation `163070921` |
| App key | Secrets Manager `kinglet/github-app`; backup in 1Password (Private vault, "kinglet bot key" — filed as an SSH key, but it is a PKCS#1 RSA key) |
| Enrolled repos | `wendyck/calendar-digest`, `wendyck/csa-wrangler` |
| Guardrails | input `460y8sih9wtm` v2 (prompt-attack only), output `lubjaymwc18i` v1 |
| Artifact bucket | `kinglet-artifacts-${ACCOUNT_ID}-us-west-2`, 7-day expiry |
| CI eval role | `kinglet-ci-evals`, stack `kinglet-ci`, trusted only from `refs/heads/main` |

The App needs `pull_requests: write` and **not** `issues: write` — labels come
through the pulls API.

---

## 5a. The polling interval is load-bearing

`rate(6 hours)` in `template.yaml`. **Two alarms are tuned to it**:
`kinglet-poller-errors` uses a 21600s period (one interval) and
`kinglet-poller-silent` uses 25200s (one interval plus an hour of slack).

Change the interval and you must change both, or they quietly stop meaning
anything. An error alarm whose period is shorter than the polling interval can
never see two consecutive runs; a silence alarm whose period is shorter than
the interval fires constantly.

## 6. Things that look fine and are not

A short list of failure modes this system has actually produced, all of which
presented as healthy:

- **An SNS topic with no subscriptions.** Alarms fire, actions succeed, nothing
  arrives. Check `list-subscriptions-by-topic`, and confirm `SubscriptionArn` is
  a real ARN rather than `PendingConfirmation`.
- **An eval that cannot tell "passed" from "did not run".** `redteam.py` once
  reported `0/5 contained` when it meant "could not authenticate". It now
  reports harness failures separately and exits non-zero.
- **An alarm that only fires on data that exists.** `Errors` is emitted only
  when something is invoked, which is why `kinglet-poller-silent` treats missing
  data as breaching.
- **A coverage index that claims coverage it does not have.** Adversarial corpus
  cases name their tests in `covered_by`, and a meta-test asserts those tests
  exist.
- **An expired SSO token.** Surfaces as almost anything else — empty replies,
  parse failures, "no JSON object". Check it first.
