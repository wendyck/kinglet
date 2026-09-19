# Kinglet reviewer image (SPEC.md §5.3) — Tier 2, untrusted.
#
# Nothing in this image holds a credential. At runtime the task has no route to
# the internet, a read-only root filesystem, and a tmpfs for /work.
#
# Base is pinned by digest, not by tag. openclaw 2026.9.5 requires
# Node >=24.16 <25 || >=26.1, so `24-slim` is both a floor and a ceiling: a
# future Node 25 tag would break the install (spike S1-S4, F6).
#
# Target platform is linux/arm64 (Fargate ARM64). Build with:
#   docker build --platform=linux/arm64 -t kinglet-reviewer reviewer/
FROM node:24-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6

ARG OPENCLAW_VERSION=2026.9.5

# openclaw writes state even for a read-only audit, so its state dir must be
# writable. It deliberately does NOT live under /work: §5.3 has the entrypoint
# `chmod -R a-w /work` once the bundle is extracted, which would otherwise break
# every openclaw invocation. /work and /state are separate tmpfs mounts at
# runtime (SPEC.md §9).

# Python runs the fs-readonly MCP server. Bookworm ships 3.11.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/kinglet/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /opt/kinglet/requirements.txt boto3

# openclaw and four transitive packages run install scripts. Naming them
# explicitly means a NEW script-bearing dependency fails the build instead of
# executing silently (spike S1-S4, F6).
# The Bedrock provider ships as a separate plugin. openclaw will fetch it from
# npm on first use if it is missing — which would be a runtime network call in a
# container that has no internet (spike F19). Install it at build time.
RUN npm config set allow-scripts=openclaw,@google/genai,koffi,tree-sitter-bash,protobufjs --location=user \
    && npm i -g "openclaw@${OPENCLAW_VERSION}" \
                "@openclaw/amazon-bedrock-provider@${OPENCLAW_VERSION}" \
    && npm cache clean --force

RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 kinglet \
    && mkdir -p /state /work \
    && chown kinglet:kinglet /state /work \
    && chmod 700 /state

WORKDIR /opt/kinglet
COPY openclaw/openclaw.json  /opt/kinglet/openclaw/openclaw.json
COPY policy_gate.py          /opt/kinglet/policy_gate.py
COPY prompt.md               /opt/kinglet/prompt.md
COPY entrypoint.py           /opt/kinglet/entrypoint.py
COPY fs_readonly/            /opt/kinglet/fs_readonly/
COPY skills/                 /opt/kinglet/skills/

# The security audit flags a world-readable config as critical, and it is right
# to: a config can carry tokens. Ours must be readable only by the run user.
RUN chown -R kinglet:kinglet /opt/kinglet \
    && chmod 600 /opt/kinglet/openclaw/openclaw.json

ENV PYTHONPATH=/opt/kinglet \
    PYTHONDONTWRITEBYTECODE=1 \
    OPENCLAW_CONFIG_PATH=/opt/kinglet/openclaw/openclaw.json \
    OPENCLAW_STATE_DIR=/state \
    NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false

USER kinglet

# The policy gate runs as the final build step and fails the build on any
# posture drift (SPEC.md §8, "fails the build on any non-conformance").
RUN python3 /opt/kinglet/policy_gate.py

# Smoke-test the MCP server at build time: an import error here is far cheaper
# to find now than in a Fargate task.
RUN python3 -c "from fs_readonly import server; print('fs_readonly imports OK')"

ENTRYPOINT ["python3", "/opt/kinglet/entrypoint.py"]
