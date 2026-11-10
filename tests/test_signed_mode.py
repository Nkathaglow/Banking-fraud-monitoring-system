import time

import pytest

from tests.conftest import KEYS
from tests.helpers import tx


@pytest.fixture(autouse=True)
def signed_mode(configure):
    configure(AUTH_MODE="signed")


def test_valid_signed_request_accepted(api):
    assert api.signed("/predict", tx()).json()["decision"] == "APPROVE"


def test_bearer_key_not_accepted_in_signed_mode(api):
    assert api.post("/predict", tx()).status_code == 401


def test_unsigned_rejected(api):
    assert api.post("/predict", tx(), auth=False).status_code == 401


def test_wrong_secret_and_unknown_client_rejected(api):
    assert api.signed("/predict", tx(), secret="z" * 48).status_code == 401
    assert api.signed("/predict", tx(), client="nobody").status_code == 401


def test_tampered_body_rejected(api):
    assert api.signed("/predict", raw=b'{"amount": 1}', sign_body=b'{"x":1}').status_code == 401


def test_replay_rejected(api):
    kw = dict(nonce="n" * 24, timestamp=str(int(time.time())))
    assert api.signed("/predict", tx(), **kw).status_code == 200
    assert api.signed("/predict", tx(), **kw).status_code == 401


def test_stale_timestamp_rejected(api):
    assert api.signed("/predict", tx(), timestamp=str(int(time.time()) - 3600)).status_code == 401


def test_roles_enforced_when_signed(api):
    assert api.signed("/predict", tx(), client="telco-feed").status_code == 403
    r = api.signed("/telco/sim-events", {"account_id": "ACC-1001", "event_type": "SIM_SWAP"}, client="telco-feed")
    assert r.status_code == 201