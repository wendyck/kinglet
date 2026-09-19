import json, urllib.request, pathlib
REPOS = ["wendyck/calendar-digest", "wendyck/csa-wrangler"]
UA = {"User-Agent": "kinglet-s5-spike", "Accept": "application/vnd.github+json"}
def get(u):
    return json.load(urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=30))
root = pathlib.Path("tests/fixtures/real")
KEEP_PR = ["number","title","state","created_at","updated_at","body"]
for repo in REPOS:
    for pr in get(f"https://api.github.com/repos/{repo}/pulls?state=open&per_page=100"):
        if pr["user"]["login"] != "dependabot[bot]":
            continue
        commits = get(pr["commits_url"] + "?per_page=100")
        files = get(f"https://api.github.com/repos/{repo}/pulls/{pr['number']}/files?per_page=100")
        snap = {
            "repo": repo,
            "pr": {k: pr[k] for k in KEEP_PR},
            "user": {"login": pr["user"]["login"], "type": pr["user"]["type"]},
            "head": {"sha": pr["head"]["sha"], "ref": pr["head"]["ref"],
                     "repo_full_name": pr["head"]["repo"]["full_name"]},
            "base": {"ref": pr["base"]["ref"], "repo_full_name": pr["base"]["repo"]["full_name"]},
            "commits": [{"sha": c["sha"], "message": c["commit"]["message"],
                         "author_login": c["author"]["login"] if c["author"] else None}
                        for c in commits],
            "changed_files": [{"filename": f["filename"], "status": f["status"],
                               "additions": f["additions"], "deletions": f["deletions"],
                               "patch": f.get("patch")} for f in files],
        }
        name = f"{repo.split('/')[1]}-pr{pr['number']}.json"
        (root / name).write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n")
        print(f"  {name}  files={[f['filename'] for f in files]}")
