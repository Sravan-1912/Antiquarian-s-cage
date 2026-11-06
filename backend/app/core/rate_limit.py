"""Fixed-window rate limiter backed by Redis, with an in-process fallback for development/tests."""
from __future__ import annotations

import logging
import threading
import time

from app.core.config import get_settings

log = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self) -> None:
        self._redis = None
        self._lock = threading.Lock()
        self._memory: dict[str, tuple[int, float]] = {}
        url = get_settings().redis_url
        if url:
            import redis

            self._redis = redis.Redis.from_url(url, socket_timeout=1)

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Register a hit; return True if the caller is still within the limit."""
        if self._redis is not None:
            try:
                bucket = f"rl:{key}:{int(time.time() // window_seconds)}"
                pipe = self._redis.pipeline()
                pipe.incr(bucket)
                pipe.expire(bucket, window_seconds)
                count, _ = pipe.execute()
                return int(count) <= limit
            except Exception:  # fail closed in production, open-with-warning in dev
                log.exception("rate limiter redis failure")
                if get_settings().environment == "production":
                    return False
        now = time.time()
        with self._lock:
            count, reset = self._memory.get(key, (0, now + window_seconds))
            if now > reset:
                count, reset = 0, now + window_seconds
            count += 1
            self._memory[key] = (count, reset)
            return count <= limit

    def reset(self) -> None:
        with self._lock:
            self._memory.clear()


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter
