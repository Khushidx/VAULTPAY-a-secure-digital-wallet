"""
Rate Limiter Utility - Sliding Window Lockout Algorithm.

Provides brute-force attack mitigation by tracking and throttling
repeated failed login attempts per IP and username using an in-memory
timestamp-based sliding window algorithm.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock


class LoginRateLimiter:
    """
    In-memory rate limiter with sliding window / lockout support.
    Thread-safe implementation for educational and production simulations.
    """

    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 300):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._attempts = defaultdict(list)  # key -> list of UTC timestamps
        self._lock = Lock()

    def _clean_expired(self, key: str, now: datetime) -> None:
        """Removes attempts older than the lockout window."""
        cutoff = now - timedelta(seconds=self.lockout_seconds)
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]

    def is_rate_limited(self, key: str) -> tuple[bool, int]:
        """
        Checks if the specified key (IP or username) is currently rate-limited.
        
        Returns:
            tuple[bool, int]: (is_limited, seconds_remaining)
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            self._clean_expired(key, now)
            attempts = self._attempts[key]
            if len(attempts) >= self.max_attempts:
                oldest_in_window = attempts[0]
                elapsed = (now - oldest_in_window).total_seconds()
                remaining = max(1, int(self.lockout_seconds - elapsed))
                return True, remaining
            return False, 0

    def record_failed_attempt(self, key: str) -> int:
        """
        Records a failed attempt for the given key.
        
        Returns:
            int: Number of attempts within the current window.
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            self._clean_expired(key, now)
            self._attempts[key].append(now)
            return len(self._attempts[key])

    def reset(self, key: str) -> None:
        """Resets the failed attempt counter for the given key (called on successful login)."""
        with self._lock:
            if key in self._attempts:
                del self._attempts[key]

    def clear_all(self) -> None:
        """Clears all stored rate limit history (useful during automated testing)."""
        with self._lock:
            self._attempts.clear()


# Global login rate limiter instance (5 failed attempts locks account/IP for 5 minutes)
login_limiter = LoginRateLimiter(max_attempts=5, lockout_seconds=300)
