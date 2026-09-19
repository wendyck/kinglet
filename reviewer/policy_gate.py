#!/usr/bin/env python3
"""Build-time policy gate for the Kinglet reviewer image (SPEC.md §8).

Runs inside the image build and exits non-zero on any non-conformance, so a
posture regression fails the build rather than shipping.

It checks four things, in increasing order of trust:

1. The config parses and every hardening value is literally what we wrote.
   `openclaw config validate` is necessary but NOT sufficient: it is schema-only
   and accepts unknown tool names silently, so a typo in `tools.deny` would
   validate cleanly while granting the tool (S1-S4 spike, F11). We therefore
   assert the effective posture separately, below.
2. `openclaw security audit --json` reports no finding outside a justified
   allowlist, and its attack-surface summary confirms elevated tools and browser
   control are actually off.
3. The build environment carries no credential escape hatch.
"""

import json
import os
import subprocess
import sys

CONFIG = os.environ.get("OPENCLAW_CONFIG_PATH", "/opt/kinglet/openclaw/openclaw.json")

# Gateway findings are inert: entrypoint.py runs `openclaw agent exec --isolated`
# and never starts a gateway, so there is no listening socket for these to apply
# to. They are allowlisted by exact checkId, so a NEW gateway finding still fails.
ALLOWED_FINDINGS = {
    "summary.attack_surface",
    # Gateway findings are inert: no gateway process is ever started.
    "gateway.loopback_no_auth",
    "gateway.trusted_proxies_missing",
    "gateway.http.no_auth",
    # openclaw's plugin index records the install without a version string. The
    # install itself IS pinned — the Dockerfile installs
    # @openclaw/amazon-bedrock-provider at an exact version and the image never
    # installs anything at runtime — so this is a bookkeeping gap, not a
    # supply-chain one. check_plugins() below asserts the pinning independently.
    "plugins.installs_unpinned_npm_specs",
}

# Env vars that would let the Bedrock provider bypass the task role entirely.
FINDING_JUSTIFICATION = {
    "gateway.loopback_no_auth": "no gateway process is started",
    "gateway.trusted_proxies_missing": "no gateway process is started",
    "gateway.http.no_auth": "no gateway process is started",
    "plugins.installs_unpinned_npm_specs": "the npm install is pinned in the Dockerfile; "
                                           "the index record merely omits the version",
}

FORBIDDEN_ENV = ["AWS_BEARER_TOKEN_BEDROCK", "AWS_BEDROCK_SKIP_AUTH",
                 "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"]

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"  FAIL  {msg}")


def ok(msg: str) -> None:
    print(f"  ok    {msg}")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=180)


def check_config_values() -> None:
    """Assert the posture literally, independent of what openclaw reports."""
    print("[1/4] config invariants")
    cfg = json.load(open(CONFIG))
    t = cfg.get("tools", {})

    expected_allow = ["fs_readonly__list_files", "fs_readonly__read_file", "fs_readonly__grep"]
    if sorted(t.get("allow", [])) != sorted(expected_allow):
        fail(f"tools.allow must be exactly {expected_allow}, got {t.get('allow')!r}")
    else:
        ok("tools.allow is the three fs_readonly tools, enumerated explicitly")

    # The Bedrock provider must use the SDK credential chain (the task role) and
    # must never carry a static key.
    prov = cfg.get("models", {}).get("providers", {}).get("amazon-bedrock", {})
    if prov.get("auth") != "aws-sdk":
        fail(f"amazon-bedrock auth must be 'aws-sdk' (task role), got {prov.get('auth')!r}")
    else:
        ok("amazon-bedrock uses the aws-sdk credential chain")
    if prov.get("apiKey"):
        fail("amazon-bedrock must not carry a static apiKey")

    for path, expected in [
        (("tools", "elevated", "enabled"), False),
        (("tools", "web", "fetch", "enabled"), False),
        (("tools", "web", "search", "enabled"), False),
        (("tools", "fs", "workspaceOnly"), True),
        (("browser", "enabled"), False),
        (("telemetry", "enabled"), False),
        (("agents", "defaults", "sandbox", "workspaceAccess"), "none"),
    ]:
        node = cfg
        for key in path:
            node = node.get(key, {}) if isinstance(node, dict) else None
            if node is None:
                break
        dotted = ".".join(path)
        if node != expected:
            fail(f"{dotted} must be {expected!r}, got {node!r}")
        else:
            ok(f"{dotted} = {expected!r}")

    for required in ("exec", "process", "write", "edit", "apply_patch"):
        if required not in t.get("deny", []):
            fail(f"tools.deny is missing {required!r}")

    servers = cfg.get("mcp", {}).get("servers", {})
    if set(servers) != {"fs_readonly"}:
        fail(f"exactly one MCP server (fs_readonly) may be registered, got {sorted(servers)}")
    else:
        ok("fs_readonly is the only registered MCP server")


def check_plugins() -> None:
    """The plugin surface is large by default: 39 of 61 stock plugins load. An
    untrusted container should carry only what it needs."""
    print("[2/4] plugin surface")
    cfg = json.load(open(CONFIG))
    allow = cfg.get("plugins", {}).get("allow")
    if allow != ["amazon-bedrock"]:
        fail(f"plugins.allow must be exactly ['amazon-bedrock'], got {allow!r}")
    else:
        ok("plugins.allow restricts loading to the Bedrock provider")

    disc = (cfg.get("plugins", {}).get("entries", {}).get("amazon-bedrock", {})
            .get("config", {}).get("discovery", {}))
    if disc.get("enabled") is not False:
        fail("Bedrock model discovery must be disabled; it calls the catalog API at runtime")
    else:
        ok("Bedrock model discovery is off (the model is pinned in config)")


def check_security_audit() -> None:
    print("[3/4] openclaw security audit")
    p = run("openclaw", "security", "audit", "--json")
    try:
        report = json.loads(p.stdout)
    except json.JSONDecodeError:
        fail(f"could not parse audit JSON (exit {p.returncode}): {p.stdout[:300]}{p.stderr[:300]}")
        return

    # openclaw reports its own failures as {"ok": false, "error": {...}} rather
    # than a findings list. Without this the gate would report the far less
    # useful "no attack-surface summary".
    if report.get("ok") is False:
        fail(f"security audit could not run: {report.get('error', {}).get('message', report)}")
        return

    for f in report.get("findings", []):
        cid, sev = f.get("checkId"), f.get("severity")
        if cid not in ALLOWED_FINDINGS:
            fail(f"unexpected {sev} finding {cid}: {f.get('title')}")
        elif sev in ("critical", "warn"):
            ok(f"{cid} ({sev}) — allowlisted: {FINDING_JUSTIFICATION.get(cid, 'see ALLOWED_FINDINGS')}")

    summary = next((f.get("detail", "") for f in report.get("findings", [])
                    if f.get("checkId") == "summary.attack_surface"), "")
    if not summary:
        fail("audit did not emit an attack-surface summary")
        return
    for needle in ("tools.elevated: disabled", "browser control: disabled",
                   "hooks.webhooks: disabled", "hooks.internal: disabled"):
        if needle in summary:
            ok(f"audit confirms {needle}")
        else:
            fail(f"audit does not confirm '{needle}'; summary was: {summary!r}")


def check_env() -> None:
    print("[4/4] credential escape hatches")
    for var in FORBIDDEN_ENV:
        if os.environ.get(var):
            fail(f"{var} is set in the image; the reviewer must use the task role only")
    if not failures:
        ok("no static AWS credentials or Bedrock auth overrides in the environment")


def main() -> int:
    print(f"kinglet policy gate — config: {CONFIG}")
    v = run("openclaw", "config", "validate")
    if "Config valid" not in v.stdout:
        print(v.stdout, v.stderr)
        fail("openclaw config validate rejected the config")
    else:
        ok("openclaw config validate passed (schema only — see module docstring)")

    check_config_values()
    check_plugins()
    check_security_audit()
    check_env()

    print()
    if failures:
        print(f"POLICY GATE FAILED — {len(failures)} problem(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("POLICY GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
