"""GitHub App authentication and a small REST client (SPEC.md §5.2, §5.5, §10).

This module holds the only credential in the system. Two rules follow from that,
and both are enforced here rather than left to callers:

- **Every installation token is down-scoped.** `installation_token()` requires an
  explicit repository list and permission set. There is no "give me everything"
  path, so Prepare cannot accidentally hold write access and Finalize cannot
  accidentally hold `contents`.
- **The private key never leaves this module.** It is fetched from Secrets
  Manager, held in memory for the life of the execution environment, and used
  only to sign short-lived JWTs.

Verified against App 5003415 on 2026-09-19: `pull_requests: write` alone is
sufficient to list, apply, remove and delete labels, so no `issues` permission
is requested anywhere.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from functools import lru_cache

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

API = "https://api.github.com"
USER_AGENT = "kinglet"
API_VERSION = "2022-11-28"

# A JWT may live at most 10 minutes. Nine leaves room for clock skew both ways.
JWT_TTL_SECONDS = 540
JWT_BACKDATE_SECONDS = 60

RETRY_STATUSES = {500, 502, 503, 504}
MAX_RETRIES = 3


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"{status} {message}" + (f" ({url})" if url else ""))
        self.status = status
        self.message = message


@dataclass(frozen=True)
class AppCredentials:
    app_id: str
    private_key_pem: str


@lru_cache(maxsize=1)
def load_credentials(secret_id: str | None = None) -> AppCredentials:
    """Read `{app_id, private_key}` from Secrets Manager (§9).

    Cached for the life of the execution environment: a warm Lambda re-signing a
    JWT should not re-read the secret on every invocation.
    """
    import boto3  # imported lazily so the pure modules stay importable offline

    secret_id = secret_id or os.environ.get("KINGLET_APP_SECRET", "kinglet/github-app")
    raw = boto3.client("secretsmanager").get_secret_value(SecretId=secret_id)["SecretString"]
    data = json.loads(raw)
    return AppCredentials(app_id=str(data["app_id"]), private_key_pem=data["private_key"])


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def app_jwt(creds: AppCredentials, now: int | None = None) -> str:
    """A short-lived RS256 JWT identifying the App itself."""
    now = int(now if now is not None else time.time())
    key = serialization.load_pem_private_key(creds.private_key_pem.encode(), password=None)
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(
        {"iat": now - JWT_BACKDATE_SECONDS, "exp": now + JWT_TTL_SECONDS, "iss": creds.app_id},
        separators=(",", ":")).encode())
    signing_input = header + b"." + payload
    signature = _b64(key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))
    return (signing_input + b"." + signature).decode()


def request(path_or_url: str, *, token: str, bearer: bool = False, method: str = "GET",
            data: dict | None = None, accept: str = "application/vnd.github+json") -> tuple[dict, dict]:
    """One REST call. Returns (parsed body, response headers).

    Retries 5xx and secondary rate limits; does not retry 4xx, which are
    deterministic and usually mean a permission is missing.
    """
    url = path_or_url if path_or_url.startswith("http") else API + path_or_url
    body = json.dumps(data).encode() if data is not None else None
    scheme = "Bearer" if bearer else "token"

    last: Exception | None = None
    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(url, data=body, method=method, headers={
            "Authorization": f"{scheme} {token}",
            "Accept": accept,
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
            **({"Content-Type": "application/json"} if body else {}),
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                parsed = json.loads(raw) if raw else {}
                return parsed, dict(r.headers)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            retry_after = e.headers.get("Retry-After") if e.headers else None
            if e.code in RETRY_STATUSES or (e.code == 403 and retry_after):
                last = GitHubError(e.code, detail, url)
                time.sleep(float(retry_after) if retry_after else 2 ** attempt)
                continue
            raise GitHubError(e.code, detail, url) from None
        except urllib.error.URLError as e:
            last = e
            time.sleep(2 ** attempt)
    raise GitHubError(599, f"exhausted retries: {last}", url)


def paginate(path: str, *, token: str, accept: str = "application/vnd.github+json",
             key: str | None = None, cap: int = 10) -> list:
    """Follow `Link: rel="next"`, up to `cap` pages.

    The cap is deliberate: a repo with thousands of open PRs should not turn one
    poll into a hundred API calls.
    """
    out: list = []
    url = path
    for _ in range(cap):
        body, headers = request(url, token=token, accept=accept)
        page = body.get(key, []) if key else body
        if isinstance(page, list):
            out.extend(page)
        link = headers.get("Link") or headers.get("link") or ""
        nxt = None
        for part in link.split(","):
            if 'rel="next"' in part:
                nxt = part.split(";")[0].strip().strip("<>")
                break
        if not nxt:
            break
        url = nxt
    return out


class GitHubApp:
    """Mints tokens. Holds the key; hands out nothing else."""

    def __init__(self, creds: AppCredentials | None = None):
        self._creds = creds or load_credentials()

    def jwt(self) -> str:
        return app_jwt(self._creds)

    def installations(self) -> list[dict]:
        return request("/app/installations", token=self.jwt(), bearer=True)[0]

    def installation_token(self, installation_id: int, *, repositories: list[str],
                           permissions: dict[str, str]) -> str:
        """A token scoped to specific repos and specific permissions.

        Both arguments are required. A caller that wants broad access has to say
        so explicitly and visibly, which is the point.
        """
        if not repositories:
            raise ValueError("installation_token requires an explicit repository list")
        if not permissions:
            raise ValueError("installation_token requires an explicit permission set")
        body, _ = request(
            f"/app/installations/{installation_id}/access_tokens",
            token=self.jwt(), bearer=True, method="POST",
            data={"repositories": repositories, "permissions": permissions})
        return body["token"]

    def discovery_token(self, installation_id: int) -> str:
        """The one token that is not repo-scoped, because it cannot be.

        Listing an installation's repositories requires an installation token,
        and scoping that token needs the repository list we are trying to
        discover. The circularity is GitHub's, not ours.

        It is made safe by permission rather than by scope: `metadata: read` is
        the weakest permission the App holds, and grants nothing beyond names
        and visibility. Every other token in Kinglet names its repositories.
        """
        body, _ = request(
            f"/app/installations/{installation_id}/access_tokens",
            token=self.jwt(), bearer=True, method="POST",
            data={"permissions": {"metadata": "read"}})
        return body["token"]

    def installation_repositories(self, installation_id: int) -> list[str]:
        """Full names of the repos this installation covers."""
        token = self.discovery_token(installation_id)
        repos = paginate("/installation/repositories?per_page=100",
                         token=token, key="repositories")
        return [r["full_name"] for r in repos]


# ── the calls Kinglet actually makes ─────────────────────────────────────────


def list_open_pulls(repo: str, *, token: str) -> list[dict]:
    return paginate(f"/repos/{repo}/pulls?state=open&per_page=100", token=token)


def list_pull_files(repo: str, number: int, *, token: str) -> list[dict]:
    return paginate(f"/repos/{repo}/pulls/{number}/files?per_page=100", token=token)


def list_pull_commits(repo: str, number: int, *, token: str) -> list[dict]:
    return paginate(f"/repos/{repo}/pulls/{number}/commits?per_page=100", token=token)


def list_issue_comments(repo: str, number: int, *, token: str) -> list[dict]:
    return paginate(f"/repos/{repo}/issues/{number}/comments?per_page=100", token=token)


def create_comment(repo: str, number: int, body: str, *, token: str) -> dict:
    return request(f"/repos/{repo}/issues/{number}/comments", token=token,
                   method="POST", data={"body": body})[0]


def update_comment(repo: str, comment_id: int, body: str, *, token: str) -> dict:
    return request(f"/repos/{repo}/issues/comments/{comment_id}", token=token,
                   method="PATCH", data={"body": body})[0]


def delete_comment(repo: str, comment_id: int, *, token: str) -> None:
    request(f"/repos/{repo}/issues/comments/{comment_id}", token=token, method="DELETE")


def set_labels(repo: str, number: int, labels: list[str], *, token: str) -> list[dict]:
    """Replace the label set. Verified to work with pull_requests:write alone."""
    return request(f"/repos/{repo}/issues/{number}/labels", token=token,
                   method="PUT", data={"labels": labels})[0]


def current_labels(repo: str, number: int, *, token: str) -> list[str]:
    return [l["name"] for l in paginate(
        f"/repos/{repo}/issues/{number}/labels?per_page=100", token=token)]


def open_dependabot_alerts(repo: str, *, token: str) -> list[dict]:
    """§5.7. The only source of truth for the security banner."""
    return paginate(f"/repos/{repo}/dependabot/alerts?state=open&per_page=100", token=token)


def repo_tarball(repo: str, sha: str, *, token: str) -> str:
    """The redirect URL for the tarball at a pinned SHA (§5.2 step 4)."""
    req = urllib.request.Request(
        f"{API}/repos/{repo}/tarball/{sha}", method="GET",
        headers={"Authorization": f"token {token}", "User-Agent": USER_AGENT,
                 "X-GitHub-Api-Version": API_VERSION})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.url
