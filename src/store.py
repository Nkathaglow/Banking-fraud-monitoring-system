"""Server-side state: replay-nonce cache, request velocity, cumulative amounts.

Clients can never supply these values. RedisStore is shared across workers;
MemoryStore is for tests / single-process demos only (state resets on restart)."""
import logging
import threading
import time
import uuid
from decimal import Decimal

logger = logging.getLogger("fraud.store")


class MemoryStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._nonces: dict[str, float] = {}
        self._events: dict[str, list] = {}

    def claim_nonce(self, key: str, ttl: int) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._nonces) > 10_000:
                self._nonces = {k: v for k, v in self._nonces.items() if v > now}
            expiry = self._nonces.get(key)
            if expiry is not None and expiry > now:
                return False
            self._nonces[key] = now + ttl
            return True

    def _record(self, key: str, window: int, value: Decimal) -> list:
        now = time.monotonic()
        with self._lock:
            events = [e for e in self._events.get(key, []) if e[0] > now - window]
            events.append((now, value))
            self._events[key] = events
            return events

    def hit(self, key: str, window: int) -> int:
        return len(self._record(key, window, Decimal(0)))

    def add_amount(self, key: str, amount: Decimal, window: int) -> Decimal:
        return sum((v for _, v in self._record(key, window, amount)), Decimal(0))


class RedisStore:
    def __init__(self, client):
        self.r = client

    def claim_nonce(self, key: str, ttl: int) -> bool:
        return bool(self.r.set(key, 1, nx=True, ex=ttl))

    def _window(self, key: str, window: int, member_suffix: str) -> list:
        now = time.time()
        pipe = self.r.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {f"{uuid.uuid4().hex}:{member_suffix}": now})
        pipe.zrange(key, 0, -1)
        pipe.expire(key, window + 5)
        return pipe.execute()[2]

    def hit(self, key: str, window: int) -> int:
        return len(self._window(key, window, "0"))

    def add_amount(self, key: str, amount: Decimal, window: int) -> Decimal:
        members = self._window(key, window, str(amount))
        return sum((Decimal(m.split(":", 1)[1]) for m in members), Decimal(0))


def build_store(redis_url: str | None):
    if redis_url:
        import redis
        client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=2)
        client.ping()  # fail fast at startup
        return RedisStore(client)
    logger.warning("REDIS_URL not set: using in-memory state (single worker only, resets on restart)")
    return MemoryStore()