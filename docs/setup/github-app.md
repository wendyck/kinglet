# Creating the `kinglet-bot` GitHub App

A manual console step, done once. It has to be you — an App cannot create itself.
Needed at the **start of Phase 1**, because the Poller lists App installations to
decide which repos are enrolled (§5.1).

Nothing here posts as your account. The App is its own identity: creating it
implicitly creates the bot user `kinglet-bot[bot]`, and that is the author of
every comment and label kinglet writes.

---

## 1. Create the App

<https://github.com/settings/apps/new>

| Field | Value |
|---|---|
| **GitHub App name** | `kinglet-bot` |
| **Homepage URL** | `https://github.com/wendyck/kinglet` |
| **Description** | Automated, security-conscious triage of Dependabot pull requests. Advisory only — never merges or approves. |
| **Webhook → Active** | **unchecked** — kinglet polls; there is no ingress (§3) |
| **Where can this App be installed?** | Only on this account |

Leave callback URLs, setup URL and the device-flow options empty.

## 2. Permissions

Repository permissions — set these four and nothing else:

| Permission | Access | Used by |
|---|---|---|
| Metadata | Read-only | (mandatory) |
| Contents | Read-only | Prepare — tarball at `head_sha` (§5.2) |
| Dependabot alerts | Read-only | Prepare — the security banner (§5.7) |
| Pull requests | Read and write | Poller (read), Finalize (write, down-scoped) |

Subscribe to no events. Every permission here is the *ceiling*; each call mints a
token narrowed further, to one repo and the one permission it needs.

> **Resolved 2026-09-19.** `pull_requests: write` is enough to list, apply,
> remove *and* delete labels on a pull request — verified against
> `csa-wrangler` #29 with a token scoped to that one repo and permission. Do not
> add **Issues** access; it is not needed.

## 3. Avatar

Upload `docs/assets/kinglet.png` as the App's avatar, so review comments carry
the same bird as the README.

App settings → *Display information* → *Upload a logo*.

## 4. Private key

*Generate a private key* downloads a `.pem` **once**. Treat it as the crown
jewel: it is the only credential in the whole system, and it lives in Tier 1
only. The reviewer container never sees it (§3).

Put it straight into Secrets Manager in us-west-2 and delete the local copy:

```bash
aws secretsmanager create-secret \
  --profile kinglet --region us-west-2 \
  --name kinglet/github-app \
  --secret-string "$(python3 -c '
import json,sys
print(json.dumps({"app_id": sys.argv[1], "private_key": open(sys.argv[2]).read()}))
' "$APP_ID" ~/Downloads/kinglet-bot.*.private-key.pem)"

shred -u ~/Downloads/kinglet-bot.*.private-key.pem 2>/dev/null || rm -P ~/Downloads/kinglet-bot.*.private-key.pem
```

`$APP_ID` is the numeric **App ID** on the App's General page — not the client ID.

Rotation, per §10: generate a new key, update the secret, then revoke the old one.

## 5. Install it

*Install App* → your account → **Only select repositories**:

- `wendyck/calendar-digest`
- `wendyck/csa-wrangler`

Both the installation *and* `config/repos.yml` must list a repo before kinglet
reviews it (§5.1). Two independent switches, so an accidental install does not
start a review.

## 6. Done — recorded here for reference

App ID **5003415**, installation **163070921**, installed on
`wendyck/calendar-digest` and `wendyck/csa-wrangler`. The secret lives at
`kinglet/github-app` in us-west-2 as `{app_id, private_key}`.

Verified end to end on 2026-09-19: the key signs a JWT that `GET /app`
accepts; the App reports exactly the four permissions above with `events: none`;
a Prepare-scoped token gets read-only access; a Finalize-scoped token gets
`pull_requests: write` and no contents access.

## What this replaces

On GitLab the equivalent is a machine-user account with a long-lived token. There
is no analogue here and no account to create, secure or pay for: the App has no
password, no 2FA, its own rate limit, and can be uninstalled from a single repo
without touching anything else.
