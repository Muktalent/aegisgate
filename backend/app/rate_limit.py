"""In-memory limiter for failed sign-in attempts.

Single-process only, which matches the single-instance Academic deployment.
State is lost on restart; that is acceptable for a short lockout window.
"""
import time
from collections.abc import Callable, Hashable


class FailureRateLimiter:
    def __init__(self, max_failures: int = 5, window_seconds: int = 300,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if max_failures < 1 or window_seconds < 1:
            raise ValueError("max_failures and window_seconds must be positive.")
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._clock = clock
        self._failures: dict[Hashable, list[float]] = {}

    def _recent(self, key: Hashable) -> list[float]:
        limit = self._clock() - self.window_seconds
        recent = [moment for moment in self._failures.get(key, []) if moment > limit]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def retry_after(self, key: Hashable) -> int:
        """Seconds until another attempt is allowed; 0 when not blocked."""
        recent = self._recent(key)
        if len(recent) < self.max_failures:
            return 0
        return max(1, int(recent[0] + self.window_seconds - self._clock()) + 1)

    def record_failure(self, key: Hashable) -> None:
        self._recent(key)
        self._failures.setdefault(key, []).append(self._clock())

    def reset(self, key: Hashable | None = None) -> None:
        if key is None:
            self._failures.clear()
        else:
            self._failures.pop(key, None)
