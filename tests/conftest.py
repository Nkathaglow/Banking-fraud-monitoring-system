import hashlib
import json
import os

KEYS = {"mobile-app": "fgk_" + "t" * 43, "telco-feed": "fgk_" + "x" * 43, "swagger-tester": "fgk_" + "v" * 43}
SECRETS = {"mobile-app": "t" * 48, "telco-feed": "x" * 48, "swagger-tester": "v" * 48}
_ROLES = {"mobile-app": "txn", "telco-feed": "telco", "swagger-tester": "txn"}

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["AUDIT_HMAC_KEY"] = "a" * 48
os.environ["MODEL_MANIFEST_KEY"] = "m" * 48
os.environ["AUTH_MODE"] = "apikey"
os.environ["GATEWAY_CLIENTS"] = json.dumps({
    name: {"role": _ROLES[name], "key_sha256": hashlib.sha256(KEYS[name].encode()).hexdigest(),
           "secret": SECRETS[name], **({"verbose": True} if name == "swagger-tester" else {})}
    for name in KEYS
})
for var in ("REDIS_URL", "REQUIRE_HTTPS", "ENABLE_DOCS", "CLIENT_RATE_LIMIT"):
    os.environ.pop(var, None)

from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src import deps  # noqa: E402
from src.app import app  # noqa: E402
from src.config import get_settings  # noqa: E402
from src.database import Base, engine, init_db  # noqa: E402
from src.signing import sign_headers  # noqa: E402
from src.store import MemoryStore  # noqa: E402


class StubBundle:
    model_sha256 = "0" * 64

    def __init__(self):
        self.probability = 0.01

    def score(self, tx):
        return self.probability


class Api:
    def __init__(self, client):
        self.client = client

    @staticmethod
    def _body(payload, raw):
        return raw if raw is not None else json.dumps(payload).encode()

    def post(self, path, payload=None, client="mobile-app", raw=None, headers=None, auth=True):
        """API-key mode (default). auth=False sends no credentials."""
        h = {"Content-Type": "application/json", **(headers or {})}
        if auth:
            h["Authorization"] = f"Bearer {KEYS[client]}"
        return self.client.post(path, content=self._body(payload, raw), headers=h)

    def telco(self, payload):
        return self.post("/telco/sim-events", payload, client="telco-feed")

    def signed(self, path, payload=None, client="mobile-app", secret=None, raw=None, sign_body=None, **sign_kw):
        """Signed mode (AUTH_MODE=signed)."""
        body = self._body(payload, raw)
        h = sign_headers(client, secret or SECRETS.get(client, "q" * 48), "POST", path,
                         sign_body if sign_body is not None else body, **sign_kw)
        h["Content-Type"] = "application/json"
        return self.client.post(path, content=body, headers=h)


@pytest.fixture(autouse=True)
def state():
    Base.metadata.drop_all(engine)
    init_db()
    ns = SimpleNamespace(store=MemoryStore(), bundle=StubBundle())
    app.dependency_overrides[deps.get_store] = lambda: ns.store
    app.dependency_overrides[deps.get_bundle] = lambda: ns.bundle
    yield ns
    app.dependency_overrides.clear()


@pytest.fixture
def configure(monkeypatch):
    """Change settings (e.g. AUTH_MODE, REQUIRE_HTTPS) for one test; restored afterwards."""
    def _set(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, str(v))
        get_settings.cache_clear()
    yield _set
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.fixture
def api():
    return Api(TestClient(app))