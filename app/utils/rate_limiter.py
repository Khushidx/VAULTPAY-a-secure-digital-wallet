"""
Rate Limiter Utility (Backward Compatibility Facade).

Re-exports `LoginRateLimiter` and `login_limiter` from
`app.utils.rate_limiter_sliding_window`.
"""

from app.utils.rate_limiter_sliding_window import (
    LoginRateLimiter,
    login_limiter,
)

__all__ = [
    "LoginRateLimiter",
    "login_limiter",
]
