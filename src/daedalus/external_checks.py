from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.flags
import dns.resolver

from .email_policy import analyze_email_auth
from .dns_settings import parse_audit_nameservers


DKIM_SELECTORS = ("google", "selector1", "selector2", "default", "s1", "s2")
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
MAX_PAGE_BYTES = 256 * 1024
MAX_REDIRECTS = 5
MAX_EXTERNAL_ORIGINS = 100
MAX_COOKIE_HEADERS = 64
MAX_COOKIE_HEADER_BYTES = 8192
MAX_SECURITY_HEADER_CHARS = 2048

KNOWN_VENDORS = (
    ("googletagmanager.com", "Google Tag Manager", "Analytics"),
    ("google-analytics.com", "Google Analytics", "Analytics"),
    ("fonts.googleapis.com", "Google Fonts", "Fonts and CDN"),
    ("fonts.gstatic.com", "Google Fonts", "Fonts and CDN"),
    ("googleapis.com", "Google APIs", "Platform services"),
    ("gstatic.com", "Google", "Platform services"),
    ("doubleclick.net", "Google advertising", "Advertising"),
    ("facebook.net", "Meta", "Social and advertising"),
    ("facebook.com", "Meta", "Social and advertising"),
    ("linkedin.com", "LinkedIn", "Social and advertising"),
    ("twitter.com", "X", "Social and advertising"),
    ("x.com", "X", "Social and advertising"),
    ("youtube.com", "YouTube", "Media"),
    ("youtube-nocookie.com", "YouTube", "Media"),
    ("vimeo.com", "Vimeo", "Media"),
    ("cdnjs.cloudflare.com", "cdnjs", "CDN and libraries"),
    ("cloudflare.com", "Cloudflare", "CDN and infrastructure"),
    ("cloudflareinsights.com", "Cloudflare Web Analytics", "Analytics"),
    ("jsdelivr.net", "jsDelivr", "CDN and libraries"),
    ("unpkg.com", "UNPKG", "CDN and libraries"),
    ("cdn.tailwindcss.com", "Tailwind CSS Play CDN", "CDN and libraries"),
    ("akamai.net", "Akamai", "CDN and infrastructure"),
    ("akamaihd.net", "Akamai", "CDN and infrastructure"),
    ("cloudfront.net", "Amazon CloudFront", "CDN and infrastructure"),
    ("amazonaws.com", "Amazon Web Services", "CDN and infrastructure"),
    ("recaptcha.net", "Google reCAPTCHA", "Security service"),
    ("hotjar.com", "Hotjar", "Analytics"),
    ("segment.com", "Twilio Segment", "Analytics"),
    ("sentry.io", "Sentry", "Monitoring"),
    ("intercom.io", "Intercom", "Customer support"),
    ("stripe.com", "Stripe", "Payments"),
    ("paypal.com", "PayPal", "Payments"),
)


class ExternalCheckFailure(RuntimeError):
    def __init__(self, message: str, snapshot: dict[str, Any] | None = None):
        super().__init__(message)
        self.snapshot = snapshot or {}


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and len("".join(self.parts)) < 512:
            self.parts.append(data)

    @property
    def title(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()[:512]


class _PageResourceParser(HTMLParser):
    """Collect active resource URLs embedded in one HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str, bool]] = []
        self.base_href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values: dict[str, str] = {}
        for name, value in attrs:
            values.setdefault(name.lower(), value or "")
        tag = tag.lower()
        if tag == "base" and "href" in values:
            if self.base_href is None:
                self.base_href = values["href"]
            return
        if tag == "script" and values.get("src"):
            self.references.append(("Script", values["src"] or "", bool((values.get("integrity") or "").strip())))
        elif tag == "link" and values.get("href"):
            rel = set((values.get("rel") or "").casefold().split())
            if "stylesheet" in rel:
                kind = "Stylesheet"
            elif "modulepreload" in rel:
                kind = "Module preload"
            elif "preload" in rel:
                kind = "Preload" + (f" ({values['as'].strip()[:32]})" if values.get("as") else "")
            elif rel & {"preconnect", "dns-prefetch"}:
                kind = "Preconnect"
            else:
                return
            self.references.append((kind, values["href"] or "", bool((values.get("integrity") or "").strip())))
        elif tag == "iframe" and values.get("src"):
            self.references.append(("Embedded frame", values["src"] or "", False))
        elif tag in {"img", "source"} and values.get("src"):
            self.references.append(("Image or media", values["src"] or "", False))
        elif tag in {"video", "audio", "embed", "object"}:
            resource_url = values.get("src") or values.get("data")
            if resource_url:
                self.references.append(("Embedded media", resource_url, False))


def _vendor_for_host(host: str) -> tuple[str, str]:
    for suffix, vendor, category in KNOWN_VENDORS:
        if host == suffix or host.endswith("." + suffix):
            return vendor, category
    return "Unclassified external host", "Other"


def _declared_unpkg_package(parsed) -> tuple[str, str] | None:
    """Identify a stable exact npm version declared in UNPKG's documented URL format.

    This does not fetch or verify package bytes, execution or vulnerability status.
    Tags, ranges, prereleases and unsupported CDN formats remain unidentified.
    """
    if parsed.hostname != "unpkg.com" or parsed.username is not None or parsed.password is not None:
        return None
    match = re.fullmatch(
        r"/((?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)@"
        r"((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))(?:/[^\s]*)?",
        parsed.path,
    )
    if match is None or len(match[1]) > 214 or len(match[2]) > 64:
        return None
    return match[1], match[2]


def _external_resource_inventory(
    html: str,
    page_url: str,
    domain: str,
) -> dict[str, Any]:
    """Summarize third-party references without fetching their URLs."""
    parser = _PageResourceParser()
    parser.feed(html)
    base_domain = domain.removeprefix("www.").rstrip(".").casefold()
    resource_base = page_url
    if parser.base_href is not None:
        try:
            resolved_base = urljoin(page_url, parser.base_href.strip())
            parsed_base = urlparse(resolved_base)
            if parsed_base.scheme.casefold() not in {"data", "javascript"}:
                resource_base = resolved_base
        except ValueError:
            resource_base = page_url
    references: dict[tuple[str, str, int | None, str], int] = {}

    declared_packages: set[tuple[str, str]] = set()
    origin_counts: dict[tuple[str, str, int | None], dict[str, int]] = {}
    dependency_counts = {"http_reference_count": 0, "script_reference_count": 0, "stylesheet_reference_count": 0, "integrity_declared_reference_count": 0, "integrity_missing_reference_count": 0}
    for kind, raw_url, integrity_declared in parser.references:
        candidate = raw_url.strip()
        if not candidate or len(candidate) > 2048:
            continue
        try:
            parsed = urlparse(urljoin(resource_base, candidate))
            host = (parsed.hostname or "").rstrip(".").casefold()
            port = parsed.port
            if port == {"http": 80, "https": 443}.get(parsed.scheme.casefold()):
                port = None
        except ValueError:
            continue
        if parsed.scheme.casefold() not in {"http", "https"} or not host:
            continue
        if host == base_domain or host.endswith("." + base_domain):
            continue
        if kind in {"Script", "Stylesheet"} and port is None:
            package = _declared_unpkg_package(parsed)
            if package is not None:
                declared_packages.add(package)
        origin_key = (host, parsed.scheme.casefold(), port)
        observed = origin_counts.setdefault(origin_key, {key: 0 for key in dependency_counts})
        if parsed.scheme.casefold() == "http":
            observed["http_reference_count"] += 1
            dependency_counts["http_reference_count"] += 1
        if kind in {"Script", "Stylesheet"}:
            dependency_counts["script_reference_count" if kind == "Script" else "stylesheet_reference_count"] += 1
            dependency_counts["integrity_declared_reference_count" if integrity_declared else "integrity_missing_reference_count"] += 1
            observed["script_reference_count" if kind == "Script" else "stylesheet_reference_count"] += 1
            observed["integrity_declared_reference_count" if integrity_declared else "integrity_missing_reference_count"] += 1
        key = (host, parsed.scheme.casefold(), port, kind)
        references[key] = references.get(key, 0) + 1

    grouped: dict[tuple[str, str, int | None], dict[str, Any]] = {}
    for (host, scheme, port, kind), count in references.items():
        item = grouped.setdefault(
            (host, scheme, port),
            {
                "host": host,
                "scheme": scheme,
                "port": port,
                "vendor": _vendor_for_host(host)[0],
                "category": _vendor_for_host(host)[1],
                "resource_types": [],
                "reference_count": 0,
            },
        )
        item["resource_types"].append(kind)
        item["reference_count"] += count

    origins = sorted(
        grouped.values(),
        key=lambda item: (item["host"], item["scheme"], item["port"] or 0),
    )
    for item in origins:
        item["resource_types"] = sorted(set(item["resource_types"]))

    return {
        "dependency_package_observations": {
            "schema_version": 1, "scope": "exact_stable_unpkg_versions_in_root_html_attributes",
            "package_bytes_verified": False, "vulnerabilities_assessed": False,
            "truncated": len(declared_packages) > 100,
            "packages": [{"ecosystem": "npm", "name": name, "version": version, "source_host": "unpkg.com"}
                         for name, version in sorted(declared_packages)[:100]],
        },
        "dependency_observations": {"schema_version": 1, "scope": "returned_root_html_attributes", "integrity_validated": False, **dependency_counts},
        "external_host_count": len({item["host"] for item in origins}),
        "external_origin_count": len(origins),
        "external_reference_count": sum(item["reference_count"] for item in origins),
        "dependency_origin_observations": {
            "schema_version": 1, "scope": "returned_root_html_attributes", "integrity_validated": False,
            "truncated": len(origins) > MAX_EXTERNAL_ORIGINS,
            "origins": [{"host": item["host"], "scheme": item["scheme"], "port": item["port"],
                         **origin_counts[(item["host"], item["scheme"], item["port"]) ]}
                        for item in origins[:MAX_EXTERNAL_ORIGINS]],
        },
        "external_resources": origins[:MAX_EXTERNAL_ORIGINS],
        "external_resources_truncated": len(origins) > MAX_EXTERNAL_ORIGINS,
    }


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS with DNS resolved and validated before connecting to a fixed IP."""

    def __init__(self, host: str, connect_ip: str, timeout: float = 10.0) -> None:
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self.connect_ip = connect_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.connect_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _record_text(record_type: str, record: Any) -> str:
    if record_type == "TXT":
        return b"".join(record.strings).decode("utf-8", errors="replace")
    return record.to_text().rstrip(".")


def _resolver_error_label(exc: dns.exception.DNSException) -> str:
    if isinstance(exc, dns.resolver.NoNameservers):
        response_codes = {
            error[3]
            for error in getattr(exc, "kwargs", {}).get("errors", ())
            if isinstance(error, tuple)
            and len(error) > 3
            and error[3] in {"FORMERR", "SERVFAIL", "NOTIMP", "REFUSED"}
        }
        if response_codes:
            return ", ".join(sorted(response_codes))
        return "No DNS server answered"
    return type(exc).__name__


def run_dns_check(domain: str, *, nameservers: tuple[str, ...] = (), include_registration: bool = False, include_transparency: bool = False) -> dict[str, Any]:
    explicit = parse_audit_nameservers(" ".join(nameservers))
    resolver = dns.resolver.Resolver(configure=True)
    if explicit:
        resolver.nameservers = list(explicit)
    observed_nameservers = []
    for value in getattr(resolver, "nameservers", ()):
        if isinstance(value, str):
            try:
                observed_nameservers.extend(parse_audit_nameservers(value))
            except ValueError:
                continue
    resolver_context = {"mode": "explicit" if explicit else "system", "nameservers": observed_nameservers[:3]}

    resolver.search = []
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    # Request DNSSEC records, but do not equate an upstream AD assertion with
    # local trust-chain validation. See RFC4035 and dnspython Resolver.use_edns.
    resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)
    errors: dict[str, str] = {}
    observations: dict[str, dict[str, Any]] = {}

    def lookup(query: tuple[str, str, str]):
        name, record_type, key = query
        observation = {
            "query_name": name.casefold().rstrip("."), "record_type": record_type,
            "status": "error", "observed_ttl_seconds": None,
            "canonical_name": None, "record_count": None, "resolver_ad": None,
        }
        try:
            answers = resolver.resolve(f"{name}.", record_type, search=False)
            values = sorted({_record_text(record_type, record) for record in answers})
            ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
            if type(ttl) is int and 0 <= ttl <= 2**32 - 1:
                observation["observed_ttl_seconds"] = ttl
            canonical = getattr(answers, "canonical_name", None)
            if canonical is not None:
                observation["canonical_name"] = canonical.to_text().casefold().rstrip(".")[:253]
            flags = getattr(getattr(answers, "response", None), "flags", None)
            if isinstance(flags, int):
                observation["resolver_ad"] = bool(flags & dns.flags.AD)
            observation.update(status="answer", record_count=len(values))
            return values, observation, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
            observation.update(status="nxdomain" if isinstance(exc, dns.resolver.NXDOMAIN) else "no_answer", record_count=0)
            # A negative response may itself carry an upstream AD assertion.
            response = getattr(exc, "kwargs", {}).get("response")
            flags = getattr(response, "flags", None)
            if isinstance(flags, int):
                observation["resolver_ad"] = bool(flags & dns.flags.AD)
            return [], observation, None
        except dns.exception.DNSException as exc:
            return [], observation, _resolver_error_label(exc)
        except (OSError, ValueError) as exc:
            return [], observation, type(exc).__name__

    queries = [(domain, kind, kind) for kind in ("A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "SRV", "CAA", "DS", "DNSKEY")]
    queries.extend((f"www.{domain}", kind, f"www {kind}") for kind in ("A", "AAAA", "CNAME"))
    queries.append((f"_dmarc.{domain}", "TXT", "DMARC"))
    queries.extend((f"{selector}._domainkey.{domain}", "TXT", f"DKIM {selector}") for selector in DKIM_SELECTORS)
    results = {}
    # Resolver configuration is fixed before concurrent resolve calls. Workers
    # return isolated observations; merge in query order for stable snapshots.
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="daedalus-dns") as pool:
        for query, (values, observation, error) in zip(queries, pool.map(lookup, queries)):
            key = query[2]
            results[key] = values
            observations[key] = observation
            if error is not None:
                errors[key] = error
    records: dict[str, Any] = {kind: results[kind] for _, kind, key in queries if kind == key}
    records.update({f"WWW_{kind}": results[f"www {kind}"] for kind in ("A", "AAAA", "CNAME")})

    records["SPF"] = sorted(
        # Retain malformed SPF-looking values for the policy interpreter.
        # Do not strip the saved evidence or turn leading whitespace valid.
        value for value in records["TXT"] if value.lstrip().casefold().startswith("v=spf1")
    )
    records["DMARC"] = results["DMARC"]
    records["DKIM"] = {
        selector: results[f"DKIM {selector}"]
        for selector in DKIM_SELECTORS
    }
    email_authentication_assessment = analyze_email_auth(records, errors)
    ds_present = None if "DS" in errors else bool(records["DS"])
    dnskey_present = None if "DNSKEY" in errors else bool(records["DNSKEY"])
    assessment = (
        "lookup_incomplete" if ds_present is None or dnskey_present is None else
        "records_observed" if ds_present or dnskey_present else "no_records_observed"
    )
    snapshot = {
        "domain": domain, "records": records, "resolver_errors": errors,
        "email_authentication_assessment": email_authentication_assessment,
        "query_observations": observations,
        "resolver_context": resolver_context,
        "dnssec_observations": {
            "assessment": assessment,
            "delegation_ds_present": ds_present,
            "zone_dnskey_present": dnskey_present,
            "resolver_ad_by_query": {key: observations[key]["resolver_ad"] for key in ("DS", "DNSKEY")},
            "local_chain_validation_performed": False,
        },
    }
    if include_registration:
        from .registration_checks import run_registration_check
        snapshot["registration_observations"] = run_registration_check(domain)
    if include_transparency:
        from .certificate_transparency import run_transparency_check
        snapshot["certificate_transparency"] = run_transparency_check(domain)
    return snapshot


def _public_addresses(host: str) -> list[str]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.search = []
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    found: set[str] = set()
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(f"{host}.", record_type, search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            continue
        for answer in answers:
            address = str(answer)
            parsed = ipaddress.ip_address(address)
            if not parsed.is_global:
                raise ExternalCheckFailure(
                    "The website hostname resolves to a non-public address; the request was blocked."
                )
            found.add(address)
    if not found:
        raise ExternalCheckFailure("No public A or AAAA address was found for the website hostname.")
    return sorted(found, key=lambda value: (ipaddress.ip_address(value).version, value))


def _cert_name(value: Any) -> str:
    parts: list[str] = []
    for group in value or ():
        for key, item in group:
            parts.append(f"{key}={item}")
    return ", ".join(parts)


def _certificate_snapshot(connection: _PinnedHTTPSConnection) -> dict[str, Any]:
    if connection.sock is None:
        raise ExternalCheckFailure("The HTTPS connection closed before its certificate could be read.")
    cert = connection.sock.getpeercert()
    der = connection.sock.getpeercert(binary_form=True)
    if not cert or not der:
        raise ExternalCheckFailure("The server did not provide a readable TLS certificate.")
    san = sorted(value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS")
    try:
        not_before = ssl.cert_time_to_seconds(cert["notBefore"])
        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    except (KeyError, ValueError) as exc:
        raise ExternalCheckFailure("The TLS certificate validity dates could not be read.") from exc
    from datetime import UTC, datetime

    protocol = connection.sock.version()
    cipher = connection.sock.cipher()
    cipher_name = cipher[0] if isinstance(cipher, tuple) and len(cipher) == 3 else None
    cipher_bits = cipher[2] if isinstance(cipher, tuple) and len(cipher) == 3 else None
    return {
        "issuer": _cert_name(cert.get("issuer")),
        "subject": _cert_name(cert.get("subject")),
        "dns_names": san,
        "valid_from": datetime.fromtimestamp(not_before, UTC).isoformat(),
        "valid_until": datetime.fromtimestamp(not_after, UTC).isoformat(),
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "negotiated_protocol": protocol[:32] if isinstance(protocol, str) else None,
        "negotiated_cipher": cipher_name[:120] if isinstance(cipher_name, str) else None,
        "cipher_secret_bits": cipher_bits if type(cipher_bits) is int and 0 <= cipher_bits <= 4096 else None,
        "supported_protocols_tested": False,
    }


def _cookie_attribute_observations(values: list[str]) -> dict[str, Any]:
    """Aggregate response attributes; cookie names and values never leave here."""
    observation: dict[str, Any] = {
        "response_header_count": len(values), "inspected_cookie_count": 0,
        "secure_attribute_count": 0, "http_only_attribute_count": 0,
        "same_site_strict_count": 0, "same_site_lax_count": 0,
        "same_site_none_count": 0, "same_site_missing_count": 0,
        "same_site_unrecognized_count": 0, "same_site_none_without_secure_count": 0,
        "unparsed_header_count": 0, "analysis_partial": len(values) > MAX_COOKIE_HEADERS,
        "scope": "final_response_headers_only",
    }
    pair = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+=")
    for value in values[:MAX_COOKIE_HEADERS]:
        if not isinstance(value, str) or len(value.encode("utf-8", errors="replace")) > MAX_COOKIE_HEADER_BYTES:
            observation["unparsed_header_count"] += 1
            observation["analysis_partial"] = True
            continue
        parts = value.split(";")
        # A combined Set-Cookie field or malformed pair cannot establish a
        # trustworthy per-cookie observation. Expires commas occur later.
        if not pair.match(parts[0].strip()) or "," in parts[0] or any(ord(c) < 32 for c in value):
            observation["unparsed_header_count"] += 1
            continue
        attributes: dict[str, list[str]] = {}
        for part in parts[1:]:
            name, _, attribute_value = part.strip().partition("=")
            attributes.setdefault(name.casefold(), []).append(attribute_value.strip())
        if any(len(attributes.get(name, [])) > 1 for name in ("secure", "httponly", "samesite")):
            observation["unparsed_header_count"] += 1
            continue
        observation["inspected_cookie_count"] += 1
        secure = "secure" in attributes
        observation["secure_attribute_count"] += int(secure)
        observation["http_only_attribute_count"] += int("httponly" in attributes)
        same_site = attributes.get("samesite", [None])[0]
        if same_site is None:
            observation["same_site_missing_count"] += 1
        elif same_site.casefold() in {"strict", "lax", "none"}:
            kind = same_site.casefold()
            observation[f"same_site_{kind}_count"] += 1
            observation["same_site_none_without_secure_count"] += int(kind == "none" and not secure)
        else:
            observation["same_site_unrecognized_count"] += 1
    return observation


def _header_semantic_observations(headers: dict[str, str | None], counts: dict[str, int], partial: bool) -> dict[str, Any]:
    """Recognize a bounded subset of directives; this is not a policy validator."""
    hsts = headers.get("strict-transport-security")
    hsts_observation: dict[str, Any] = {"state": "missing", "max_age_seconds": None, "include_subdomains": None, "preload_token_present": None}
    if hsts:
        directives: dict[str, list[str]] = {}
        for directive in hsts.split(";"):
            name, _, value = directive.strip().partition("=")
            directives.setdefault(name.casefold(), []).append(value.strip())
        ages = directives.get("max-age", [])
        hsts_observation["state"] = "unrecognized"
        if counts.get("strict-transport-security", 0) != 1 or len(ages) != 1 or any(len(values) > 1 for values in directives.values()):
            hsts_observation["state"] = "ambiguous"
        elif re.fullmatch(r'[0-9]{1,18}|"[0-9]{1,18}"', ages[0]):
            hsts_observation.update(
                state="observed", max_age_seconds=int(ages[0].strip('"')),
                include_subdomains="includesubdomains" in directives,
                preload_token_present="preload" in directives,
            )
    csp = headers.get("content-security-policy") or ""
    names = {part.strip().split()[0].casefold() for part in csp.split(";") if part.strip()}
    tokens = csp.split()
    return {
        "analysis_partial": partial, "scope": "recognized_response_header_tokens_only",
        "hsts": hsts_observation,
        "csp": {
            "header_observed": bool(csp), "header_count": counts.get("content-security-policy", 0),
            "default_src_token_present": "default-src" in names,
            "frame_ancestors_token_present": "frame-ancestors" in names,
            "unsafe_inline_token_present": any(token.rstrip(";,") == "'unsafe-inline'" for token in tokens),
            "unsafe_eval_token_present": any(token.rstrip(";,") == "'unsafe-eval'" for token in tokens),
            "nonce_source_present": bool(re.search(r"'nonce-[^']+'", csp)),
        },
        "x_content_type_options": {
            "header_observed": bool(headers.get("x-content-type-options")),
            "nosniff_value_recognized": (headers.get("x-content-type-options") or "").casefold() == "nosniff",
        },
        "x_frame_options": {
            "header_observed": bool(headers.get("x-frame-options")),
            "recognized_value": (headers.get("x-frame-options") or "").upper() if (headers.get("x-frame-options") or "").upper() in {"DENY", "SAMEORIGIN"} else None,
        },
    }


def _validate_redirect(current_url: str, location: str, allowed_hosts: set[str]) -> str:
    next_url = urljoin(current_url, location)
    parsed = urlparse(next_url)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.hostname not in allowed_hosts
        or parsed.port not in (None, 443)
    ):
        raise ExternalCheckFailure(
            "The website redirected outside its HTTPS domain; the redirect was blocked."
        )
    return next_url


def run_website_check(domain: str) -> dict[str, Any]:
    base_domain = domain.removeprefix("www.")
    allowed_hosts = {base_domain, f"www.{base_domain}"}
    current_url = f"https://{domain}/"
    snapshot: dict[str, Any] = {
        "requested_url": current_url,
        "destination_addresses": [],
        "redirects": [],
    }

    for redirect_number in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)
        host = parsed.hostname or ""
        if host not in allowed_hosts or parsed.scheme != "https":
            raise ExternalCheckFailure("The request target was outside the allowed HTTPS domain.", snapshot)
        try:
            addresses = _public_addresses(host)
        except ExternalCheckFailure as exc:
            raise ExternalCheckFailure(str(exc), snapshot) from exc
        snapshot["destination_addresses"] = addresses
        connection: _PinnedHTTPSConnection | None = None
        try:
            connection = _PinnedHTTPSConnection(host, addresses[0])
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request(
                "GET",
                path,
                headers={
                    "User-Agent": "Daedalus-Passive-Health-Check/1.0",
                    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            cert_snapshot = _certificate_snapshot(connection)
            response = connection.getresponse()
            response_headers: dict[str, str | None] = {}
            header_counts: dict[str, int] = {}
            header_partial = False
            for header in SECURITY_HEADERS:
                values = response.headers.get_all(header) or []
                normalized = ", ".join(" ".join(value.split()) for value in values)
                header_counts[header] = len(values)
                header_partial = header_partial or len(normalized) > MAX_SECURITY_HEADER_CHARS
                response_headers[header] = normalized[:MAX_SECURITY_HEADER_CHARS] or None

            if response.status in {301, 302, 303, 307, 308} and response.getheader("Location"):
                if redirect_number >= MAX_REDIRECTS:
                    raise ExternalCheckFailure("The website exceeded the redirect limit.", snapshot)
                next_url = _validate_redirect(current_url, response.getheader("Location"), allowed_hosts)
                snapshot["redirects"].append({"status": response.status, "url": next_url})
                current_url = next_url
                continue

            header_observations = _header_semantic_observations(response_headers, header_counts, header_partial)
            if response_headers.get("content-security-policy"):
                response_headers["content-security-policy"] = re.sub(r"'nonce-[^']*(?:'|$)", "'nonce-[redacted]'", response_headers["content-security-policy"])
            cookie_observations = _cookie_attribute_observations(response.headers.get_all("Set-Cookie") or [])
            content_type = response.getheader("Content-Type", "")
            # Retain observed response evidence even if reading the body fails.
            # Page content and dependency evidence require a completed read.
            snapshot.update({
                "final_url": current_url,
                "http_status": response.status,
                "http_reason": response.reason[:120] if response.reason else "",
                "content_type": content_type[:256],
                "security_headers": response_headers,
                "tls": cert_snapshot,
                "cookie_observations": cookie_observations,
                "header_observations": header_observations,
            })
            body = response.read(MAX_PAGE_BYTES + 1)
            html_truncated = len(body) > MAX_PAGE_BYTES
            body = body[:MAX_PAGE_BYTES]
            declared_length = response.getheader("Content-Length")
            length_incomplete = False
            if declared_length is not None:
                if re.fullmatch(r"[0-9]{1,12}", declared_length.strip()):
                    length_incomplete = int(declared_length) != len(body)
                else:
                    length_incomplete = True
            representation_partial = html_truncated or response.status == 206 or bool(response.getheader("Content-Range")) or length_incomplete
            title = ""
            external_inventory = {
                "external_host_count": 0,
                "external_origin_count": 0,
                "external_reference_count": 0,
                "external_resources": [],
                "external_resources_truncated": False,
                "page_html_truncated": html_truncated,
            }
            if "html" in content_type.casefold():
                page_html = body.decode("utf-8", errors="replace")
                parser = _TitleParser()
                parser.feed(page_html)
                title = parser.title
                external_inventory = _external_resource_inventory(
                    page_html,
                    current_url,
                    base_domain,
                )
            external_inventory["page_html_truncated"] = html_truncated
            snapshot.update(
                {
                    "final_url": current_url,
                    "http_status": response.status,
                    "http_reason": response.reason[:120] if response.reason else "",
                    "content_type": content_type[:256],
                    "title": title,
                    "security_headers": response_headers,
                    "tls": cert_snapshot,
                    "cookie_observations": cookie_observations,
                    "header_observations": header_observations,
                    "page_content": {
                        "algorithm": "sha256", "sha256": hashlib.sha256(body).hexdigest(),
                        "sampled_bytes": len(body), "partial": representation_partial,
                        "comparison_eligible": not representation_partial and 200 <= response.status < 300 and response.getheader("Content-Encoding", "identity").casefold() in {"", "identity"},
                    },
                    **external_inventory,
                }
            )
            return snapshot
        except ExternalCheckFailure as exc:
            raise ExternalCheckFailure(str(exc), {**snapshot, **exc.snapshot}) from exc
        except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError) as exc:
            raise ExternalCheckFailure(
                f"HTTPS request failed ({type(exc).__name__}).", snapshot
            ) from exc
        finally:
            if connection is not None:
                connection.close()
    raise ExternalCheckFailure("The website redirect limit was exceeded.", snapshot)


def flatten_snapshot(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(flatten_snapshot(value[key], path))
    elif prefix:
        flattened[prefix] = value
    return flattened


def _canonical_origin_list(value: Any) -> list[dict[str, Any]] | None:
    """Normalize historical default-port aliases without rewriting saved evidence."""
    if not isinstance(value, list):
        return None
    grouped = {}
    for row in value:
        if not isinstance(row, dict):
            return None
        item = dict(row)
        # Provider labels are derived from our classification catalog, not
        # observed changes to the website's dependencies. Retain them in the
        # saved snapshot while comparing the actual origin evidence.
        item.pop("vendor", None)
        item.pop("category", None)
        host, scheme, port = item.get("host"), item.get("scheme"), item.get("port")
        if not isinstance(host, str) or not isinstance(scheme, str) or scheme not in {"http", "https"} or "port" not in item:
            return None
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            return None
        if port == {"http": 80, "https": 443}[scheme]:
            item["port"] = port = None
        key = (host, scheme, port)
        if key not in grouped:
            grouped[key] = item
            continue
        existing = grouped[key]
        if existing.keys() != item.keys():
            return None
        for field, entry in item.items():
            if field.endswith("_count"):
                if any(type(count) is not int or count < 0 for count in (existing[field], entry)):
                    return None
                existing[field] += entry
            elif field == "resource_types":
                if not all(isinstance(types, list) and all(isinstance(t, str) for t in types)
                           for types in (existing[field], entry)):
                    return None
                existing[field] = sorted(set(existing[field] + entry))
            elif existing[field] != entry:
                return None
    return sorted(grouped.values(), key=lambda row: (row["host"], row["scheme"], row["port"] or 0))


def compare_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> list[tuple[str, Any, Any]]:
    old_values = flatten_snapshot(previous)
    new_values = flatten_snapshot(current)
    for values, snapshot in ((old_values, previous), (new_values, current)):
        resources = _canonical_origin_list(snapshot.get("external_resources"))
        if resources is not None:
            values["external_resources"] = resources
            if snapshot.get("external_resources_truncated") is False:
                values["external_origin_count"] = len(resources)
        block = snapshot.get("dependency_origin_observations")
        if isinstance(block, dict):
            origins = _canonical_origin_list(block.get("origins"))
            if origins is not None:
                values["dependency_origin_observations.origins"] = origins
    # Resolver diagnostics are useful evidence in each saved snapshot, but the
    # exact exception text is transient (for example SERVFAIL vs timeout) and
    # should not be presented as a DNS configuration change. Compare whether
    # each lookup was available while retaining the original errors in runs.
    for values, snapshot in ((old_values, previous), (new_values, current)):
        errors = snapshot.get("resolver_errors")
        if isinstance(errors, dict):
            for lookup in errors:
                values[f"resolver_errors.{lookup}"] = "unavailable"
    paths = old_values.keys() & new_values.keys()
    error_paths = {
        path
        for path in old_values.keys() | new_values.keys()
        if path.startswith("resolver_errors.")
    }

    def incomplete_record_paths(snapshot: dict[str, Any]) -> set[str]:
        paths: set[str] = set()
        errors = snapshot.get("resolver_errors")
        if errors is not None and (
            not isinstance(errors, dict) or not all(isinstance(key, str) for key in errors)
        ):
            # Corrupt lookup metadata cannot establish which DNS observations
            # were available. Preserve the snapshots, but do not infer DNS
            # configuration changes from them. Other evidence remains comparable.
            return {"records", "query_observations", "dnssec_observations",
                    "email_authentication_assessment", "resolver_errors"}
        for lookup in (errors or {}):
            # Missing metadata from an unavailable response is not a change
            # to records or DNSSEC protection. Availability is compared above.
            paths.add(f"query_observations.{lookup}")
            if lookup in {"DS", "DNSKEY"}:
                paths.add("dnssec_observations.assessment")
                paths.add(f"dnssec_observations.resolver_ad_by_query.{lookup}")
                paths.add("dnssec_observations.delegation_ds_present" if lookup == "DS"
                          else "dnssec_observations.zone_dnskey_present")
            if lookup == "TXT":
                paths.update({
                    "records.TXT", "records.SPF",
                    "email_authentication_assessment.spf",
                })
            elif lookup == "DMARC":
                paths.update({
                    "records.DMARC",
                    "email_authentication_assessment.dmarc",
                })
            elif lookup.startswith("DKIM "):
                paths.add(f"records.DKIM.{lookup.removeprefix('DKIM ')}")
            elif lookup.startswith("www "):
                record_type = lookup.removeprefix("www ").upper()
                paths.add(f"records.WWW_{record_type}")
            else:
                paths.add(f"records.{lookup}")
        return paths

    incomplete_paths = incomplete_record_paths(previous) | incomplete_record_paths(current)
    def incomplete_page(snapshot: dict[str, Any]) -> bool:
        evidence = snapshot.get("page_content")
        status = snapshot.get("http_status")
        return (
            isinstance(evidence, dict) and evidence.get("comparison_eligible") is False
            or snapshot.get("page_html_truncated") is True
            or type(status) is int and not 200 <= status < 300
        )

    page_incomplete = any(incomplete_page(snapshot) for snapshot in (previous, current))
    cookies_incomplete = any(
        isinstance(snapshot.get("cookie_observations"), dict)
        and (snapshot["cookie_observations"].get("analysis_partial") is True
             or snapshot["cookie_observations"].get("unparsed_header_count", 0) > 0)
        for snapshot in (previous, current)
    )
    changes = []
    for path in sorted(paths | error_paths):
        if path.startswith("certificate_transparency."):
            if path not in {"certificate_transparency.state", "certificate_transparency.collection_partial"}:
                continue
            blocks = [snapshot.get("certificate_transparency") for snapshot in (previous, current)]
            if not all(isinstance(block, dict) and block.get("provider") == "crt.sh"
                       and block.get("scope") == "domain_and_subdomains"
                       and block.get("domain") == snapshot.get("domain")
                       for block, snapshot in zip(blocks, (previous, current))) or previous.get("domain") != current.get("domain"):
                continue
        if path.startswith("registration_observations."):
            field = path.removeprefix("registration_observations.")
            if field not in {"state", "collection_partial", "registrars", "nameservers", "events"}:
                continue
            blocks = [snapshot.get("registration_observations") for snapshot in (previous, current)]
            if not all(isinstance(block, dict) and block.get("protocol") == "rdap"
                       and block.get("domain") == snapshot.get("domain")
                       for block, snapshot in zip(blocks, (previous, current))):
                continue
            if previous.get("domain") != current.get("domain"):
                continue
            if field not in {"state", "collection_partial"} and not (
                all(block.get("state") == "observed" and block.get("collection_partial") is False for block in blocks)
                and blocks[0].get("source_url") == blocks[1].get("source_url")
            ):
                continue
        if cookies_incomplete and path.startswith("cookie_observations.") and path not in {
            "cookie_observations.analysis_partial", "cookie_observations.unparsed_header_count",
        }:
            # A bounded or ambiguous sample cannot establish that cookie
            # attributes disappeared. Keep completeness changes and evidence.
            continue
        if path == "dependency_origin_observations" or path.startswith("dependency_origin_observations."):
            if page_incomplete or not all(isinstance(snapshot.get("dependency_origin_observations"), dict)
                and snapshot["dependency_origin_observations"].get("schema_version") == 1
                and snapshot["dependency_origin_observations"].get("truncated") is False
                for snapshot in (previous, current)):
                continue
            if path != "dependency_origin_observations.origins":
                continue
        if path == "dependency_advisory_observations" or path.startswith("dependency_advisory_observations."):
            blocks = [snapshot.get("dependency_advisory_observations") for snapshot in (previous, current)]
            if not all(isinstance(block, dict) and block.get("schema_version") == 1 for block in blocks):
                continue
            if path == "dependency_advisory_observations.packages":
                if page_incomplete or not all(block.get("state") == "observed" for block in blocks):
                    continue
            elif path != "dependency_advisory_observations.state":
                continue
        if path == "dependency_package_observations" or path.startswith("dependency_package_observations."):
            if path != "dependency_package_observations.packages" or page_incomplete:
                continue
            package_metadata = [snapshot.get("dependency_package_observations") for snapshot in (previous, current)]
            if not all(isinstance(item, dict) and item.get("schema_version") == 1
                       and item.get("truncated") is False for item in package_metadata):
                continue
        if path == "dependency_observations" or path.startswith("dependency_observations."):
            if page_incomplete or not all((snapshot.get("dependency_observations") or {}).get("schema_version") == 1 for snapshot in (previous, current)):
                continue
            if path in {"dependency_observations.schema_version", "dependency_observations.scope", "dependency_observations.integrity_validated"}:
                continue
        if path == "resolver_context" or path.startswith("resolver_context."):
            continue
        # Recursive resolver TTL is remaining cache lifetime, not an authoritative
        # configuration change. Retain it as report evidence without alert churn.
        if path.startswith("query_observations.") and path.endswith(".observed_ttl_seconds"):
            continue
        if page_incomplete and path in {"title", "external_resources", "external_host_count", "external_origin_count", "external_reference_count"}:
            # An error page or truncated/encoded sample is not evidence that
            # the site's real title or linked vendors were removed or changed.
            continue
        if path.startswith("page_content."):
            if not all((snapshot.get("page_content") or {}).get("comparison_eligible") is True for snapshot in (previous, current)):
                continue
            if previous.get("final_url") != current.get("final_url") or previous.get("content_type") != current.get("content_type"):
                continue
        if any(path == incomplete or path.startswith(incomplete + ".") for incomplete in incomplete_paths):
            continue
        old = old_values.get(path)
        new = new_values.get(path)
        if path == "registration_observations.events":
            from .registration_checks import canonical_registration_events
            try:
                if canonical_registration_events(old) == canonical_registration_events(new):
                    continue
            except (ValueError, OverflowError):
                # Unreadable dates cannot establish a registration change.
                continue
        if old != new or (path not in old_values) != (path not in new_values):
            changes.append((path, old, new))
    if previous.get("domain") == current.get("domain") and isinstance(current.get("domain"), str):
        from .certificate_transparency import newly_observed_entries
        additions = newly_observed_entries(previous.get("certificate_transparency"), current.get("certificate_transparency"), current["domain"])
        if additions:
            changes.append(("certificate_transparency.newly_observed_entries", [], additions))
    return changes
