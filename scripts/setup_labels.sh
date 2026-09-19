#!/usr/bin/env bash
# Create the three risk labels on a repo (SPEC.md §7.4, §10).
#
# This is about presentation, not permission. Kinglet can apply a label that
# does not exist — verified 2026-09-19, pull_requests:write is enough to create
# one implicitly — but GitHub then picks the colour. Running this first means
# the labels come out green / amber / red with descriptions, rather than three
# arbitrary shades.
#
# Uses your own `gh` auth on purpose, so the App does not need `issues: write`.
#
# Usage: scripts/setup_labels.sh wendyck/csa-wrangler

set -euo pipefail

REPO="${1:?usage: setup_labels.sh <owner/repo>}"

command -v gh >/dev/null || { echo "gh CLI not found: brew install gh" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated: gh auth login" >&2; exit 1; }

create_or_update () {
  local name="$1" colour="$2" description="$3"
  if gh label list --repo "$REPO" --json name --jq '.[].name' | grep -qx "$name"; then
    gh label edit "$name" --repo "$REPO" --color "$colour" --description "$description"
    echo "  updated $name"
  else
    gh label create "$name" --repo "$REPO" --color "$colour" --description "$description"
    echo "  created $name"
  fi
}

echo "Setting up risk labels on $REPO"
create_or_update "risk:low"    "0e8a16" "Kinglet: low-risk dependency update"
create_or_update "risk:medium" "fbca04" "Kinglet: review before merging"
create_or_update "risk:high"   "d93f0b" "Kinglet: needs careful review"
echo "Done."
