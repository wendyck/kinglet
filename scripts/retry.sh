#!/usr/bin/env bash
# Re-run a review that failed (SPEC.md §5.8).
#
# The failure path records the review key with status=failed so the poller does
# not loop on a PR that cannot be reviewed. That is the right default and the
# reason a retry has to be deliberate: this deletes the marker comment, which
# makes the PR a candidate again on the next poll.
#
# Usage: scripts/retry.sh wendyck/csa-wrangler 29

set -euo pipefail

REPO="${1:?usage: retry.sh <owner/repo> <pr>}"
PR="${2:?usage: retry.sh <owner/repo> <pr>}"
BOT="${KINGLET_BOT_LOGIN:-kinglet-bot[bot]}"

command -v gh >/dev/null || { echo "gh CLI not found: brew install gh" >&2; exit 1; }

echo "Looking for kinglet's comment on $REPO#$PR..."
ID=$(gh api "repos/$REPO/issues/$PR/comments" --paginate \
  --jq "[.[] | select(.user.login == \"$BOT\") | select(.body | contains(\"<!-- kinglet:v1 \"))] | .[0].id // empty")

if [ -z "$ID" ]; then
  echo "No kinglet review comment found. The PR is already a candidate."
  exit 0
fi

STATUS=$(gh api "repos/$REPO/issues/comments/$ID" --jq '.body' | sed -n 's/.*status=\([a-z]*\).*/\1/p' | head -1)
echo "Found comment $ID (status=${STATUS:-unknown})."
read -r -p "Delete it so the next poll re-reviews this PR? [y/N] " reply
[ "$reply" = "y" ] || { echo "Aborted."; exit 1; }

gh api -X DELETE "repos/$REPO/issues/comments/$ID"
echo "Deleted. The next poll (up to 10 minutes) will pick this PR up again."
