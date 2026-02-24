from collections import defaultdict, deque
from threading import Lock
from time import time
from typing import cast

from app.core.config import settings


class SecurityStore:
    def __init__(self):
        self._redis = None
        self._prefix = settings.redis_prefix
        self._memory_rate: dict[str, deque[float]] = defaultdict(deque)
        self._memory_blacklist: dict[str, float] = {}
        self._lock = Lock()
        if settings.redis_url:
            try:
                from redis import Redis

                self._redis = Redis.from_url(settings.redis_url, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    def _rk(self, key: str) -> str:
        return f'{self._prefix}:{key}'

    @property
    def redis_enabled(self) -> bool:
        return self._redis is not None

    def allow_rate_limit(self, key: str, limit: int, window_seconds: int) -> bool:
        if self._redis is not None:
            redis_key = self._rk(f'rl:{key}')
            current = cast(int, self._redis.incr(redis_key))
            if current == 1:
                self._redis.expire(redis_key, window_seconds)
            return current <= limit

        now = time()
        boundary = now - window_seconds
        with self._lock:
            bucket = self._memory_rate[key]
            while bucket and bucket[0] <= boundary:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    def blacklist_token(self, jti: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if self._redis is not None:
            self._redis.setex(self._rk(f'bl:{jti}'), ttl_seconds, '1')
            return
        with self._lock:
            self._memory_blacklist[jti] = time() + ttl_seconds

    def is_blacklisted(self, jti: str) -> bool:
        if self._redis is not None:
            return self._redis.exists(self._rk(f'bl:{jti}')) == 1
        now = time()
        with self._lock:
            expired = [k for k, exp in self._memory_blacklist.items() if exp <= now]
            for key in expired:
                del self._memory_blacklist[key]
            exp = self._memory_blacklist.get(jti)
            return exp is not None and exp > now

    def reset_local_state(self) -> None:
        with self._lock:
            self._memory_rate.clear()
            self._memory_blacklist.clear()
