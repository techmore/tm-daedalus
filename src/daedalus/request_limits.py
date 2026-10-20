"""Bound request bodies on routes whose handlers parse JSON before they can check its size.

FastAPI reads and parses a JSON body before route dependencies run, so a handler
cannot reject an oversized body early. This ASGI middleware caps the body for the
configured method/path patterns both by Content-Length and by streaming, so a
chunked upload is rejected as soon as it exceeds the limit instead of being
buffered first. Routes that stream their own body (artifact uploads, CIS reports)
keep their own caps and are not listed here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from starlette.exceptions import HTTPException


class BodyTooLarge(HTTPException):
    """Raised from the wrapped receive; FastAPI re-raises HTTPException from its body read."""

    def __init__(self, limit: int):
        super().__init__(status_code=413, detail=_detail(limit), headers={"Cache-Control": "no-store"})


class BoundedBodyMiddleware:
    def __init__(self, app, rules: Iterable[tuple[str, str, int]]):
        """`rules` holds (method, path regex, byte limit) triples; the first match wins."""
        self.app = app
        self.rules = [(method.upper(), re.compile(pattern), int(limit)) for method, pattern, limit in rules]

    def limit_for(self, method: str, path: str) -> int | None:
        for rule_method, pattern, limit in self.rules:
            if rule_method == method.upper() and pattern.fullmatch(path):
                return limit
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope.get("method", ""), scope.get("path", ""))
        if limit is None:
            await self.app(scope, receive, send)
            return
        declared = _content_length(scope.get("headers") or [])
        if declared is not None and declared > limit:
            await _reject(send, limit)
            return

        received = 0
        response_started = False

        async def bounded_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge(limit)
            return message

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, tracking_send)
        except BodyTooLarge:
            # Starlette's exception middleware normally answers first; this covers apps without it.
            if response_started:
                raise
            await _reject(send, limit)


def _content_length(headers) -> int | None:
    for name, value in headers:
        if name.lower() == b"content-length":
            try:
                return int(value.decode("latin-1").strip())
            except ValueError:
                return None
    return None


def _detail(limit: int) -> str:
    return f"Request body exceeds {limit // 1024} KB"


async def _reject(send, limit: int) -> None:
    body = json.dumps({"detail": _detail(limit)}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": body})
