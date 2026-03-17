from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from time import time

from fastapi import Depends, HTTPException, Request, status

from app.core.auth import AuthenticatedUser, get_current_user
from app.core.config import get_settings


@dataclass(frozen=True)
class RateLimitRule:
    action: str
    limit: int
    window_seconds: int


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._requests: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, *, rule: RateLimitRule, subject: str) -> None:
        now = time()
        window_start = now - rule.window_seconds
        key = (rule.action, subject)

        with self._lock:
            bucket = self._requests[key]
            while bucket and bucket[0] < window_start:
                bucket.popleft()

            if len(bucket) >= rule.limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for {rule.action}",
                )

            bucket.append(now)

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()


rate_limiter = InMemoryRateLimiter()


def _rule_for_action(action: str) -> RateLimitRule:
    settings = get_settings()
    if action == "upload":
        limit = settings.upload_rate_limit
    elif action == "review":
        limit = settings.review_rate_limit
    else:
        limit = settings.read_rate_limit
    return RateLimitRule(action=action, limit=limit, window_seconds=settings.rate_limit_window_seconds)


def enforce_rate_limit(action: str) -> Callable[[Request, AuthenticatedUser], None]:
    rule = _rule_for_action(action)

    def dependency(
        request: Request,
        current_user: AuthenticatedUser = Depends(get_current_user),
    ) -> None:
        client_host = request.client.host if request.client else "unknown"
        subject = f"{current_user.username}:{current_user.role.value}:{client_host}"
        rate_limiter.check(rule=rule, subject=subject)

    return dependency
