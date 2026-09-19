"""S5 spike: is the `updated-dependencies` trailer present and parseable on
every open Dependabot PR across the enrolled repos? (SPEC.md §5.2 step 5, §12)"""
import json, re, urllib.request, sys

REPOS = ["wendyck/calendar-digest", "wendyck/csa-wrangler"]
UA = {"User-Agent": "kinglet-s5-spike", "Accept": "application/vnd.github+json"}

def get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def authentic(pr):
    """§5.1 authenticity checks."""
    return (pr["user"]["login"] == "dependabot[bot]"
            and pr["user"]["type"] == "Bot"
            and pr["head"]["repo"] and pr["head"]["repo"]["full_name"] == pr["base"]["repo"]["full_name"]
            and pr["head"]["ref"].startswith("dependabot/"))

def trailer_block(msg):
    """Return the raw lines of the updated-dependencies block.

    The block is YAML: a `- ` sequence at column 0 with indented keys. It ends
    at the `...` YAML end-of-document marker Dependabot emits, or at the first
    line that is neither indented nor a sequence entry."""
    lines = msg.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.strip() == "updated-dependencies:")
    except StopIteration:
        return None
    out = []
    for l in lines[i + 1:]:
        if l.strip() in ("...", "---"):
            break
        if l.startswith("-") or l[:1] in (" ", "\t"):
            out.append(l)
        elif l.strip() == "":
            continue
        else:
            break
    return out

def parse_trailer(msg):
    block = trailer_block(msg)
    if not block:
        return None
    deps, cur = [], None
    for line in block:
        s = line.strip()
        if not s:
            continue
        if s.startswith("- "):
            cur = {}
            deps.append(cur)
            s = s[2:].strip()
        if cur is None or ":" not in s:
            continue
        k, _, v = s.partition(":")
        cur[k.strip()] = v.strip().strip('"').strip("'")
    return deps

total = ok = 0
for repo in REPOS:
    prs = get(f"https://api.github.com/repos/{repo}/pulls?state=open&per_page=100")
    dbots = [p for p in prs if authentic(p)]
    print(f"\n=== {repo}: {len(dbots)} authentic Dependabot PRs (of {len(prs)} open) ===")
    for pr in sorted(dbots, key=lambda p: p["number"]):
        total += 1
        commits = get(pr["commits_url"] + "?per_page=100")
        authors = {c["author"]["login"] if c["author"] else "?" for c in commits}
        msg = commits[0]["commit"]["message"]
        deps = parse_trailer(msg)
        status = "OK " if deps else "MISS"
        if deps:
            ok += 1
        print(f"  {status} #{pr['number']:<4} {pr['title'][:62]}")
        print(f"       commits={len(commits)} authors={sorted(authors)} sha={pr['head']['sha'][:12]}")
        for d in (deps or []):
            print(f"       - {d.get('dependency-name')}: {dict(d)}")
        if not deps:
            print("       !! no updated-dependencies trailer; first commit message:")
            print("       " + msg[:400].replace("\n", "\n       "))

print(f"\n==== S5: {ok}/{total} PRs had a parseable trailer ====")
sys.exit(0 if ok == total else 1)
