"""Fetch a workspace domain's public favicon for display in the workspace switcher.

Uses the website check's hardened connection: HTTPS only, public addresses only,
pinned IP, same-domain redirects only. Only small raster images are kept; SVG is
rejected because it can carry script.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from daedalus.external_checks import (
    ExternalCheckFailure, _PinnedHTTPSConnection, _public_addresses, _validate_redirect,
)

MAX_ICON_BYTES = 64 * 1024
MAX_HTML_BYTES = 256 * 1024
MAX_HOPS = 3
_MAGIC = ((b"\x89PNG\r\n\x1a\n", "image/png"), (b"\x00\x00\x01\x00", "image/x-icon"),
          (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"), (b"\xff\xd8\xff", "image/jpeg"))


def sniff_icon_type(data: bytes) -> str | None:
    for magic, kind in _MAGIC:
        if data.startswith(magic):
            return kind
    return None


class _IconLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[tuple[int, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag != "link":
            return
        values = {name: (value or "") for name, value in attrs}
        rel = set(values.get("rel", "").casefold().split())
        if "icon" in rel and values.get("href"):
            # Prefer explicit PNG, then anything else.
            self.hrefs.append((0 if "png" in values.get("type", "") or values["href"].casefold().endswith(".png") else 1, values["href"].strip()))


def _get(url: str, allowed_hosts: set[str], limit: int) -> tuple[int, dict[str, str], bytes, str]:
    current = url
    for _ in range(MAX_HOPS + 1):
        parsed = urlparse(current)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or host not in allowed_hosts:
            raise ExternalCheckFailure("Icon request left the allowed HTTPS domain.")
        addresses = _public_addresses(host)
        connection = _PinnedHTTPSConnection(host, addresses[0], timeout=8.0)
        try:
            path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
            connection.request("GET", path, headers={"User-Agent": "Daedalus-Icon-Fetch/1.0", "Accept": "image/*,text/html;q=0.8",
                                                     "Accept-Encoding": "identity", "Connection": "close"})
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308} and response.getheader("Location"):
                current = _validate_redirect(current, response.getheader("Location"), allowed_hosts)
                continue
            body = response.read(limit + 1)
            return response.status, {"content-type": response.getheader("Content-Type", "")}, body[:limit] if len(body) <= limit else b"", current
        finally:
            connection.close()
    raise ExternalCheckFailure("Too many redirects while fetching the icon.")


def fetch_site_icon(domain: str) -> tuple[str, bytes] | None:
    """Return (content_type, bytes) for the domain's favicon, or None."""
    base = domain.removeprefix("www.")
    allowed = {base, f"www.{base}"}
    candidates: list[str] = []
    try:
        status, _headers, body, final_url = _get(f"https://{domain}/", allowed, MAX_HTML_BYTES)
        if status == 200 and body:
            parser = _IconLinks()
            parser.feed(body.decode("utf-8", errors="replace"))
            for _rank, href in sorted(parser.hrefs)[:3]:
                if re.match(r"^(https://|/|[A-Za-z0-9._~\-/]+)", href) and not href.startswith("data:"):
                    candidates.append(urljoin(final_url, href))
    except ExternalCheckFailure:
        pass
    except OSError:
        pass
    candidates.append(f"https://{domain}/favicon.ico")
    for url in dict.fromkeys(candidates):
        try:
            status, _headers, body, _final = _get(url, allowed, MAX_ICON_BYTES)
        except (ExternalCheckFailure, OSError):
            continue
        kind = sniff_icon_type(body) if status == 200 and body else None
        if kind:
            return kind, body
    return None
