"""Shared HTTP helper with retry-on-5xx and redirect-following for resolvers."""

import logging

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)


class TransientHTTPError(Exception):
    """Raised when an HTTP response has a 5xx status code."""

    def __init__(self, response: httpx.Response):
        self.response = response
        super().__init__(f"HTTP {response.status_code}")


@retry(
    retry=retry_if_exception_type(
        (TransientHTTPError, httpx.ConnectError, httpx.ConnectTimeout)
    ),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(4),
    reraise=True,
)
def httpx_request(method: str, url: str, **kwargs) -> httpx.Response:
    """Issue an HTTP request via httpx with automatic retries on transient failures.

    * Follows redirects by default (``follow_redirects=True``).
    * Retries up to 4 total attempts on 5xx responses, ``ConnectError``,
      and ``ConnectTimeout`` with exponential backoff (~2 s, ~4 s, ~8 s).
    * Non-retryable errors (4xx, other exceptions) propagate immediately.
    """
    kwargs.setdefault("follow_redirects", True)
    r = httpx.request(method, url, **kwargs)
    if r.status_code >= 500:
        logger.info("Retryable %s from %s – will retry", r.status_code, url)
        raise TransientHTTPError(r)
    return r
