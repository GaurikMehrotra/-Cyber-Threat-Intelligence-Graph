"""Single-process bounded fixed-window limiter; use a shared limiter for multiworker deployments."""

import time

from fastapi import HTTPException


class RateLimiter:
    def __init__(self, maximum: int = 60, window: int = 60):
        self.maximum = maximum
        self.window = window
        self.starts = 0.0
        self.count = 0

    def check(self) -> None:
        now = time.monotonic()
        if now - self.starts >= self.window:
            self.starts = now
            self.count = 0
        if self.count >= self.maximum:
            raise HTTPException(
                429, "Rate limit exceeded", headers={"Retry-After": str(self.window)}
            )
        self.count += 1
