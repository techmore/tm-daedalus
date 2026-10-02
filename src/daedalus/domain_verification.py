from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta

import dns.exception
import dns.resolver

from daedalus.models import DomainChallenge

CHALLENGE_LABEL = "_daedalus-verification"
CHALLENGE_PREFIX = "daedalus-verification="


def normalize_domain(raw_domain: str) -> str:
    value = raw_domain.strip().rstrip(".").lower()
    if not value or "://" in value or "/" in value or "@" in value:
        raise ValueError("Enter a domain name without a URL, path, or email address.")
    try:
        domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Enter a valid DNS domain name.") from exc
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")
    if len(domain) > 253 or "." not in domain:
        raise ValueError("Enter a fully qualified domain such as example.com.")
    labels = domain.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise ValueError("The domain contains an invalid DNS label.")
    return domain


def challenge_record_name(domain: str) -> str:
    return f"{CHALLENGE_LABEL}.{domain}"


def challenge_record_value(clear_token: str) -> str:
    return CHALLENGE_PREFIX + clear_token


def issue_challenge(
    *,
    db,
    organization_id: int,
    user_id: int,
    token_hash: str,
    now: datetime,
    lifetime_days: int = 30,
) -> DomainChallenge:
    challenge = DomainChallenge(
        organization_id=organization_id,
        token_hash=token_hash,
        created_by_user_id=user_id,
        expires_at=now + timedelta(days=lifetime_days),
        created_at=now,
    )
    db.add(challenge)
    return challenge


def has_matching_txt(domain: str, token_hashes: set[str], token_digest) -> bool:
    record_name = challenge_record_name(domain)
    try:
        answers = dns.resolver.resolve(record_name, "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except dns.exception.DNSException as exc:
        raise RuntimeError("DNS lookup failed. Try again in a moment.") from exc

    for answer in answers:
        value = b"".join(answer.strings).decode("utf-8", errors="replace").strip()
        if value.startswith(CHALLENGE_PREFIX):
            token = value.removeprefix(CHALLENGE_PREFIX)
            if token_digest(token) in token_hashes:
                return True
    return False
