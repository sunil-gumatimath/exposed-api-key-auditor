"""GitHub API rate-limit handling with exponential backoff and a global
per-process token bucket to prevent concurrent-task stampedes."""

import asyncio
import logging
import time

logger = logging.getLogger(__name__)

# GitHub search API: 30 req/min for authenticated *repo* search, but
# *code* search is capped at 10 req/min even when authenticated. Start
# conservative (below 10) so the first concurrent volley doesn't blow the
# quota before any X-RateLimit header has been observed; the bucket then
# ratchets to the real value reported by the response headers.
SEARCH_QUOTA = 8

# Minimum spacing between search requests. GitHub enforces a *secondary*
# (abuse-detection) rate limit that rejects simultaneous bursts with 403,
# even when the primary 10/min budget has tokens left. Spacing requests
# ~7s apart keeps us under 10/min no matter how many tasks are concurrent.
MIN_REQUEST_INTERVAL = 7.0


def _lookup_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup (aiohttp headers are case-insensitive)."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


class RateLimiter:
    """Track GitHub API rate limits and apply backoff on 403/429.

    Uses a per-process token bucket (asyncio.Lock + shared counter) so
    N concurrent tasks don't all see X-RateLimit-Remaining > 0 on their
    first request and exhaust the quota in one barrage.
    """

    def __init__(self, max_retries: int = 5) -> None:
        self.max_retries = max_retries
        self._lock = asyncio.Lock()
        self._remaining = SEARCH_QUOTA
        self._reset_time: float = 0.0
        self._last_request_time: float = 0.0

    # ------------------------------------------------------------------
    # Public helpers called by scanner.py
    # ------------------------------------------------------------------

    async def acquire(self) -> None:
        """Block until a search-API token is available.

        Call *before* every GitHub search GET so the token bucket prevents
        concurrent tasks from collectively overshooting the quota. Also
        enforces a minimum spacing between requests to avoid GitHub's
        secondary (abuse-detection) rate limit, which rejects bursts with
        403 even when the primary quota has tokens remaining.
        """
        while True:
            async with self._lock:
                now = time.time()
                # Reset tokens if reset_time has passed
                if self._reset_time > 0 and now >= self._reset_time:
                    self._remaining = SEARCH_QUOTA
                    self._reset_time = 0.0

                # Enforce minimum spacing between consecutive requests.
                elapsed = now - self._last_request_time
                if elapsed < MIN_REQUEST_INTERVAL:
                    spacing_wait = MIN_REQUEST_INTERVAL - elapsed
                else:
                    spacing_wait = 0.0

                if self._remaining > 0 and spacing_wait == 0.0:
                    self._remaining -= 1
                    self._last_request_time = now
                    return

                # Either no tokens left, or we must wait for spacing.
                if spacing_wait > 0.0:
                    wait = spacing_wait
                elif self._reset_time > now:
                    wait = self._reset_time - now + 1.0
                else:
                    # If no reset time is known or expired, restore quota
                    self._remaining = SEARCH_QUOTA
                    wait = 0.1
            logger.debug(
                "Rate-limit throttle: waiting %.1fs (tokens remaining=%s, min_interval=%ss)",
                wait,
                self._remaining,
                MIN_REQUEST_INTERVAL,
            )
            await asyncio.sleep(wait)

    async def update_from_headers(self, headers: dict[str, str]) -> None:
        """Update the token bucket from GitHub response headers."""
        async with self._lock:
            raw_remaining = _lookup_header(headers, "X-RateLimit-Remaining")
            raw_reset = _lookup_header(headers, "X-RateLimit-Reset")
            if raw_remaining is not None:
                try:
                    self._remaining = int(raw_remaining)
                except (ValueError, TypeError):
                    pass
            if raw_reset is not None:
                try:
                    self._reset_time = float(raw_reset)
                except (ValueError, TypeError):
                    pass

    async def wait_if_needed(self, status: int, response_headers: dict[str, str]) -> None:
        """Legacy hook -- called after each response.  Also updates bucket."""
        await self.update_from_headers(response_headers)

        retry_after = _lookup_header(response_headers, "Retry-After")
        if retry_after and status in {403, 429}:
            try:
                wait_time = max(1, int(float(retry_after)))
            except (ValueError, TypeError):
                wait_time = 5
            logger.warning("Rate-limited (Retry-After). Waiting %s seconds...", wait_time)
            await asyncio.sleep(wait_time)
            return

        async with self._lock:
            remaining = self._remaining
            reset_timestamp = self._reset_time
        if remaining == 0 and reset_timestamp:
            wait_time = max(1, int(reset_timestamp - time.time() + 3))
            logger.warning("Rate limit reached. Waiting %s seconds...", wait_time)
            await asyncio.sleep(wait_time)

    async def exponential_backoff(self, attempt: int) -> None:
        wait_time = min(2**attempt, 300)
        logger.warning(
            "Backing off for %s seconds (attempt %s/%s)",
            wait_time,
            attempt + 1,
            self.max_retries,
        )
        await asyncio.sleep(wait_time)
