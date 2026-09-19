"""Tests for GitHub App auth (SPEC.md §5.2, §5.5, §10).

The point of this module is that no caller can get a broad token by accident,
so that is what these check. JWT signing is verified against a throwaway key.
"""

import base64
import json
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from common.github_app import (  # noqa: E402
    AppCredentials, GitHubApp, JWT_BACKDATE_SECONDS, JWT_TTL_SECONDS, app_jwt,
)


@pytest.fixture(scope="module")
def creds():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()).decode()
    return AppCredentials(app_id="5003415", private_key_pem=pem)


def decode(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def test_jwt_has_three_segments_and_rs256(creds):
    head, payload, sig = app_jwt(creds).split(".")
    assert decode(head) == {"alg": "RS256", "typ": "JWT"}
    assert sig


def test_jwt_claims(creds):
    now = int(time.time())
    payload = decode(app_jwt(creds, now=now).split(".")[1])
    assert payload["iss"] == "5003415"
    assert payload["iat"] == now - JWT_BACKDATE_SECONDS
    assert payload["exp"] == now + JWT_TTL_SECONDS


def test_jwt_stays_inside_githubs_ten_minute_ceiling(creds):
    payload = decode(app_jwt(creds).split(".")[1])
    assert payload["exp"] - payload["iat"] <= 600


def test_installation_token_refuses_an_empty_repository_list(creds):
    with pytest.raises(ValueError, match="repository list"):
        GitHubApp(creds).installation_token(1, repositories=[],
                                            permissions={"contents": "read"})


def test_installation_token_refuses_an_empty_permission_set(creds):
    with pytest.raises(ValueError, match="permission set"):
        GitHubApp(creds).installation_token(1, repositories=["repo"], permissions={})
