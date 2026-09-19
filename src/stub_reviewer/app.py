"""Phase 1 stub reviewer (SPEC.md §12, Phase 1).

Stands in for the Fargate task so the pipeline can be proven end to end before
the container, the VPC and the endpoints exist. It reads `meta/`, echoes the
deterministic floor back in the reviewer's own output shape, and writes
`results/`.

It deliberately claims nothing it cannot support: every verdict is `UNKNOWN`,
usage is `unknown`, and there is no evidence. A floor-only comment should look
like a floor-only comment.

This is the one component that reads `meta/` and writes `results/`, which the
real reviewer may not do — it can read only `bundles/` (§9). The stub is a Tier 1
Lambda, not Tier 2, so the boundary is not weakened; it is simply absent until
Phase 2 puts the container in its place.
"""

from __future__ import annotations

import json
import logging
import os

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

BUCKET = os.environ.get("KINGLET_BUCKET", "")


def handler(event, context):  # noqa: ARG001
    s3 = boto3.client("s3")
    meta = json.loads(
        s3.get_object(Bucket=BUCKET, Key=event["meta_key"])["Body"].read())

    packages = [
        {
            "name": p["name"],
            "directory": p["directory"],
            "risk": p.get("floor", "low"),
            "verdict": "UNKNOWN",
            "usage": "unknown",
            "reason_codes": [],
            "evidence": [],
        }
        for p in meta.get("packages", [])
    ]

    result = {
        "schema_version": 1,
        "overall_risk": meta.get("overall_floor", "low"),
        "packages": packages,
        "notes": "Floor-only review: the reviewer container is not in the "
                 "pipeline yet (Phase 1). No usage or changelog analysis was "
                 "performed.",
    }

    s3.put_object(Bucket=BUCKET, Key=event["result_key"],
                  Body=json.dumps(result).encode(),
                  ContentType="application/json")
    log.info("stub reviewed %s#%s: %d packages at floor %s",
             event.get("repo"), event.get("pr"), len(packages),
             result["overall_risk"])
    return {**event, "reviewer": "stub"}
