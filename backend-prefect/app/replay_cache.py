"""Caché Anti-Replay en memoria: (user_id, código) -> momento en que se usó."""
import threading
import time

REPLAY_TTL_SECONDS = 90  # cubre las ventanas C-1, C y C+1


class ReplayAttackDetected(Exception):
    pass


class AntiReplayCache:
    def __init__(self, ttl: int = REPLAY_TTL_SECONDS, clock=time.time):
        self._ttl = ttl
        self._clock = clock
        self._used: dict[tuple[int, str], float] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        expired = [k for k, used_at in self._used.items() if now - used_at >= self._ttl]
        for k in expired:
            del self._used[k]

    def was_used(self, user_id: int, code: str) -> bool:
        with self._lock:
            self._purge(self._clock())
            return (user_id, code) in self._used

    def seconds_since_use(self, user_id: int, code: str) -> float | None:
        with self._lock:
            used_at = self._used.get((user_id, code))
            return None if used_at is None else self._clock() - used_at

    def mark_used(self, user_id: int, code: str) -> bool:
        """Marca el código de forma atómica. Devuelve False si otra petición ya lo usó."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            if (user_id, code) in self._used:
                return False
            self._used[(user_id, code)] = now
            return True


replay_cache = AntiReplayCache()
