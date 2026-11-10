from fastapi.testclient import TestClient

from src.app import app
from src.config import get_settings
from src.schemas import SIM_EVENT_EXAMPLES, TRANSACTION_EXAMPLES
from tests.conftest import KEYS
from tests.helpers import audit_rows, tx


# ---------- authentication (API-key mode, the default) ----------
def test_health_is_public():
    assert TestClient(app).get("/health").json() == {"status": "ok"}


def test_no_credentials_rejected(api):
    r = api.post("/predict", tx(), auth=False)
    assert r.status_code == 401 and r.json() == {"detail": "Unauthorized"}
    assert r.headers["www-authenticate"] == "Bearer"


def test_wrong_key_rejected(api):
    r = api.post("/predict", tx(), auth=False, headers={"Authorization": "Bearer fgk_" + "z" * 43})
    assert r.status_code == 401


def test_legacy_static_key_and_test_key_backdoor_rejected(api):
    for key in ("test-key", "banking-secret-gateway-key-2026"):
        assert api.post("/predict", tx(), auth=False, headers={"X-API-Key": key}).status_code == 401
        assert api.post("/predict", tx(), auth=False, headers={"Authorization": f"Bearer {key}"}).status_code == 401


def test_key_in_query_string_or_wrong_scheme_rejected(api):
    r = api.client.post(f"/predict?api_key={KEYS['mobile-app']}", json=tx())
    assert r.status_code == 401
    assert api.post("/predict", tx(), auth=False,
                    headers={"Authorization": f"Basic {KEYS['mobile-app']}"}).status_code == 401


def test_key_is_not_stored_in_settings():
    assert KEYS["mobile-app"] not in repr(get_settings())  # only the SHA-256 is held server-side


def test_roles_are_enforced(api):
    assert api.post("/predict", tx(), client="telco-feed").status_code == 403
    r = api.post("/telco/sim-events", {"account_id": "ACC-1001", "event_type": "SIM_SWAP"})
    assert r.status_code == 403


def test_rate_limit_per_client(api, configure):
    configure(CLIENT_RATE_LIMIT=3)
    codes = [api.post("/predict", tx(account_id=f"ACC-{i:04d}")).status_code for i in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert api.post("/telco/sim-events", {"account_id": "ACC-1001", "event_type": "SIM_SWAP"},
                    client="telco-feed").status_code == 201  # other clients are unaffected


def test_https_enforced_when_enabled(api, configure):
    configure(REQUIRE_HTTPS="true")
    assert api.post("/predict", tx()).status_code == 400
    ok = api.post("/predict", tx(), headers={"X-Forwarded-Proto": "https"})
    assert ok.status_code == 200 and "strict-transport-security" in ok.headers
    assert TestClient(app).get("/health").status_code == 200  # health check stays reachable


# ---------- swagger usability ----------
def test_openapi_has_authorize_scheme_and_examples():
    spec = app.openapi()
    assert "HTTPBearer" in spec["components"]["securitySchemes"]
    content = spec["paths"]["/predict"]["post"]["requestBody"]["content"]["application/json"]
    assert set(content["examples"]) == set(TRANSACTION_EXAMPLES)


def test_every_swagger_example_is_valid(api):
    for name, ex in TRANSACTION_EXAMPLES.items():
        r = api.post("/predict", ex["value"], client="swagger-tester")
        assert r.status_code == 200, name
    for ex in SIM_EVENT_EXAMPLES.values():
        assert api.telco(ex["value"]).status_code == 201


def test_swagger_sim_swap_flow_blocks(api):
    api.telco(SIM_EVENT_EXAMPLES["sim_swap"]["value"])
    r = api.post("/predict", TRANSACTION_EXAMPLES["after_sim_swap"]["value"], client="swagger-tester")
    assert r.json()["decision"] == "BLOCK" and r.json()["security_threat"] == "SIM-Swap Fraud"


# ---------- response detail ----------
def test_production_client_gets_minimal_response(api):
    body = api.post("/predict", tx()).json()
    assert set(body) == {"request_id", "audit_id", "decision", "timestamp"}


def test_verbose_client_gets_score_and_reason(api, state):
    state.bundle.probability = 0.5
    body = api.post("/predict", tx(), client="swagger-tester").json()
    assert body["decision"] == "REVIEW" and body["fraud_probability"] == 0.5
    assert body["risk_level"] == "MEDIUM" and body["decision_source"] == "ML"
    assert "reason" in body and "security_threat" in body


# ---------- input validation ----------
def test_extra_fields_rejected(api):
    assert api.post("/predict", tx(malicious_injection="DROP TABLE audit_logs;")).status_code == 422


def test_client_cannot_supply_velocity_or_sim_flags(api):
    assert api.post("/predict", tx(request_velocity_per_min=1, device_changed_recently=False)).status_code == 422


def test_amount_bounds(api):
    assert api.post("/predict", tx(amount=999_999_999.0)).status_code == 422
    assert api.post("/predict", tx(amount=0)).status_code == 422
    assert api.post("/predict", tx(oldbalanceOrg=-1)).status_code == 422
    assert api.post("/predict", tx(amount=10.123)).status_code == 422


def test_unknown_type_rejected(api):
    assert api.post("/predict", tx(type="XYZ")).status_code == 422


def test_bad_account_id_rejected(api):
    assert api.post("/predict", tx(account_id="x'; DROP TABLE audit_logs;--")).status_code == 422


def test_oversized_body_rejected(api):
    assert api.post("/predict", raw=b"{" + b" " * 20000 + b"}").status_code == 413


# ---------- decisions ----------
def test_normal_payment_approved(api):
    r = api.post("/predict", tx(type="PAYMENT", amount=181.0, oldbalanceOrg=181.0, newbalanceOrig=0.0,
                                oldbalanceDest=0.0, newbalanceDest=0.0))
    assert r.status_code == 200 and r.json()["decision"] == "APPROVE"


def test_origin_ledger_violation_blocked(api):
    r = api.post("/predict", tx(type="CASH_OUT", amount=50000.0, oldbalanceOrg=100000.0,
                                newbalanceOrig=100000.0, oldbalanceDest=0.0, newbalanceDest=0.0))
    assert r.json()["decision"] == "BLOCK"
    row = audit_rows()[-1]
    assert row.security_threat == "Ledger Invariant Violation" and row.ledger_anomaly_detected


def test_destination_ledger_violation_blocked(api):
    assert api.post("/predict", tx(newbalanceDest=500.0)).json()["decision"] == "BLOCK"
    assert "destination" in audit_rows()[-1].message


def test_bot_velocity_is_server_side(api):
    decisions = [api.post("/predict", tx()).json()["decision"] for _ in range(11)]
    assert decisions[:10] == ["APPROVE"] * 10 and decisions[10] == "BLOCK"
    assert audit_rows()[-1].security_threat == "Automated Bot / Credential Stuffing"


def test_sim_swap_requires_telco_event(api):
    big = tx(amount=75000.0, oldbalanceOrg=100000.0, newbalanceOrig=25000.0,
             oldbalanceDest=0.0, newbalanceDest=75000.0)
    assert api.post("/predict", big).json()["decision"] == "APPROVE"  # no SIM event for this account
    api.telco({"account_id": "ACC-2002", "event_type": "SIM_SWAP"})
    assert api.post("/predict", {**big, "account_id": "ACC-2002"}).json()["decision"] == "BLOCK"
    assert audit_rows()[-1].security_threat == "SIM-Swap Fraud"


def test_structuring_after_sim_swap_is_caught(api):
    assert api.telco({"account_id": "ACC-1001", "event_type": "SIM_SWAP"}).status_code == 201
    first = tx(amount=30000.0, oldbalanceOrg=100000.0, newbalanceOrig=70000.0,
               oldbalanceDest=0.0, newbalanceDest=30000.0)
    second = tx(amount=30000.0, oldbalanceOrg=70000.0, newbalanceOrig=40000.0,
                oldbalanceDest=30000.0, newbalanceDest=60000.0)
    assert api.post("/predict", first).json()["decision"] == "APPROVE"
    assert api.post("/predict", second).json()["decision"] == "BLOCK"  # 60k cumulative > 50k


def test_cumulative_volume_goes_to_review(api):
    a = tx(amount=150000.0, oldbalanceOrg=1_000_000.0, newbalanceOrig=850_000.0,
           oldbalanceDest=0.0, newbalanceDest=150000.0)
    b = tx(amount=100000.0, oldbalanceOrg=850_000.0, newbalanceOrig=750_000.0,
           oldbalanceDest=0.0, newbalanceDest=100000.0)
    assert api.post("/predict", a).json()["decision"] == "APPROVE"
    assert api.post("/predict", b).json()["decision"] == "REVIEW"


def test_ml_thresholds_three_way(api, state):
    for p, expected in [(0.05, "APPROVE"), (0.5, "REVIEW"), (0.95, "BLOCK")]:
        state.bundle.probability = p
        assert api.post("/predict", tx(account_id=f"ACC-{int(p*100):04d}")).json()["decision"] == expected
    row = audit_rows()[-1]
    assert row.decision_source == "ML" and float(row.ml_probability) == 0.95


def test_rule_hit_still_records_real_ml_score(api, state):
    state.bundle.probability = 0.12
    api.post("/predict", tx(newbalanceDest=500.0))
    row = audit_rows()[-1]
    assert row.decision_source == "RULE" and float(row.ml_probability) == 0.12


def test_fail_closed_when_model_errors(api, state):
    def boom(_):
        raise RuntimeError("model down")
    state.bundle.score = boom
    r = api.post("/predict", tx())
    assert r.status_code == 503 and "model down" not in r.text