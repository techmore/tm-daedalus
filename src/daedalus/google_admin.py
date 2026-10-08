"""Bounded Google Admin reads and a CSP checklist; no tenant write operations."""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime

import httpx

PREFIX = "https://www.googleapis.com/auth/"
SCOPES = ("openid", "email", *(PREFIX + s for s in (
    "admin.directory.customer.readonly", "admin.directory.domain.readonly",
    "admin.directory.user.readonly", "admin.directory.rolemanagement.readonly",
)))
CHECKLIST_VERSION = "csp-google-admin-1.0.0"
SOURCE = "https://support.google.com/a/answer/7587183"
ADMIN_SOURCE = "https://support.google.com/a/answer/9011373"
USER_SOURCE = "https://developers.google.com/workspace/admin/directory/reference/rest/v1/users"
CHECKS = (
    ("GA-01", "Account inventory and lifecycle", "5 Account Management", "Review accounts against an approved lifecycle roster."),
    ("GA-02", "Administrator privileges and recovery", "5 Account Management; 6 Access Control Management", "Review delegated privileges, separate admin accounts and recovery procedures."),
    ("GA-03", "Recorded administrator 2-Step Verification", "6 Access Control Management", "Require 2-Step Verification enforcement and enrollment for the active administrator accounts recorded by Directory users; verify phishing-resistant factors manually."),
    ("GA-04", "Authentication and session policies", "4 Secure Configuration; 6 Access Control Management", "Capture effective password, SSO, session and recovery policy for each applicable OU/group."),
    ("GA-05", "Third-party apps and delegation", "2 Software Inventory; 6 Access Control Management; 15 Service Provider Management", "Review trusted apps, OAuth grants and domain-wide delegation against an approved inventory."),
    ("GA-06", "Gmail and sender protection", "9 Email and Web Browser Protections", "Review Gmail protections alongside SPF, DKIM and DMARC evidence."),
    ("GA-07", "Sharing boundaries", "3 Data Protection; 6 Access Control Management", "Review effective external/public sharing and documented business exceptions."),
    ("GA-08", "Audit logs, alerts and review", "8 Audit Log Management; 17 Incident Response Management", "Verify collection, retention, review ownership and alert delivery."),
    ("GA-09", "Devices and Chrome policy", "1 Enterprise Asset Inventory; 4 Secure Configuration; 9 Email and Web Browser Protections", "Capture managed device/browser enforcement and extension policy."),
    ("GA-10", "Retention, recovery and incident readiness", "3 Data Protection; 11 Data Recovery; 17 Incident Response Management", "Review retention and independently tested recovery/response procedures."),
)


class GoogleAdminError(RuntimeError):
    """Safe operational message; never includes Google response bodies or tokens."""


def validate_scopes(value: object) -> list[str]:
    if not isinstance(value, str):
        raise GoogleAdminError("Google did not confirm the granted audit scopes. Reconnect the audit account.")
    scopes = set(value.split())
    if PREFIX + "userinfo.email" in scopes:
        scopes.remove(PREFIX + "userinfo.email")
        scopes.add("email")
    if scopes != set(SCOPES):
        raise GoogleAdminError("Google granted missing or unexpected scopes. Use the dedicated audit project and reconnect.")
    return sorted(scopes)


class GoogleAdminClient:
    def __init__(self, access_token: str):
        self.access_token = access_token
        self.deadline = time.monotonic() + 120
        self.http = httpx.Client(timeout=15, follow_redirects=False)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.http.close()

    def get(self, path: str, params: dict | None = None) -> dict:
        if not re.fullmatch(r"(?:users|customers/my_customer|customer/[A-Za-z0-9_-]+/(?:domains|roles|roleassignments))", path):
            raise GoogleAdminError("Refused an unsupported Google Admin operation.")
        return self._request("GET", "https://admin.googleapis.com/admin/directory/v1/" + path,
                             params=params, headers={"Authorization": "Bearer " + self.access_token})

    def _request(self, method: str, url: str, **kwargs) -> dict:
        if not (method == "POST" and url == "https://oauth2.googleapis.com/token" or method == "GET" and url.startswith("https://admin.googleapis.com/admin/directory/v1/") and re.fullmatch(r"(?:users|customers/my_customer|customer/[A-Za-z0-9_-]+/(?:domains|roles|roleassignments))", url.removeprefix("https://admin.googleapis.com/admin/directory/v1/"))):
            raise GoogleAdminError("Refused an unsupported Google Admin operation.")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise GoogleAdminError("Google Admin collection deadline exceeded; coverage is unconfirmed.")
        try:
            with self.http.stream(method, url, timeout=min(15, remaining), **kwargs) as response:
                if response.status_code != 200:
                    raise GoogleAdminError(f"Google Admin returned HTTP {response.status_code}. Check consent, API enablement and audit-account privileges.")
                raw = bytearray()
                for block in response.iter_bytes():
                    if time.monotonic() > self.deadline:
                        raise GoogleAdminError("Google Admin collection deadline exceeded; coverage is unconfirmed.")
                    raw.extend(block)
                    if len(raw) > 2 * 1024 * 1024:
                        raise GoogleAdminError("Google Admin response exceeded the collection limit.")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except (httpx.HTTPError, ValueError) as exc:
            raise GoogleAdminError("Google Admin could not be reached or returned unreadable evidence.") from exc

    def binding(self, domain: str, expected_customer: str | None = None) -> dict:
        customer = self.get("customers/my_customer", {"fields": "id,customerDomain"})
        customer_id = customer.get("id")
        if not isinstance(customer_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", customer_id):
            raise GoogleAdminError("Google did not return a valid customer identity.")
        if expected_customer is not None and customer_id != expected_customer:
            raise GoogleAdminError("The audit account no longer matches the approved Google customer.")
        result = self.get(f"customer/{customer_id}/domains", {"fields": "domains(domainName,verified,domainAliases(domainAliasName,verified))"})
        records = result.get("domains")
        if not isinstance(records, list) or len(records) > 1000:
            raise GoogleAdminError("Google did not return bounded domain evidence.")
        domains = set()
        for item in records:
            if not isinstance(item, dict):
                raise GoogleAdminError("Google returned invalid domain evidence.")
            if item.get("verified") is True and isinstance(item.get("domainName"), str):
                domains.add(item["domainName"].lower().rstrip("."))
            for alias in item.get("domainAliases", []):
                if isinstance(alias, dict) and alias.get("verified") is True and isinstance(alias.get("domainAliasName"), str):
                    domains.add(alias["domainAliasName"].lower().rstrip("."))
        if domain.lower().rstrip(".") not in domains:
            raise GoogleAdminError("The verified workspace domain is not a verified domain of this Google customer.")
        return {"customer_id": customer_id, "domains": sorted(domains), "scope": "entire_customer"}

    def pages(self, path: str, key: str, params: dict) -> list[dict]:
        rows, seen_tokens, seen_ids = [], set(), set()
        identity = {"users": "id", "roles": "roleId", "roleassignments": "roleAssignmentId"}[path.rsplit("/", 1)[-1]]
        for _ in range(100):
            result = self.get(path, params)
            # Missing collections are ambiguous, even when Google might omit an empty list.
            items = result.get(key)
            if not isinstance(items, list) or any(not isinstance(row, dict) for row in items):
                raise GoogleAdminError("Google omitted a collection or returned invalid rows; coverage is unconfirmed.")
            for row in items:
                row_id = row.get(identity)
                if not isinstance(row_id, str) or not row_id or row_id in seen_ids:
                    raise GoogleAdminError("Google returned missing or repeated row identities; coverage is unconfirmed.")
                seen_ids.add(row_id)
            rows.extend(items)
            if len(rows) > 10000:
                raise GoogleAdminError("Google Admin inventory exceeded the bounded collection limit.")
            token = result.get("nextPageToken")
            if token is None or token == "":
                return rows
            if not isinstance(token, str) or len(token) > 4096 or token in seen_tokens:
                raise GoogleAdminError("Google returned invalid or repeated pagination; coverage is unconfirmed.")
            seen_tokens.add(token)
            params = {**params, "pageToken": token}
        raise GoogleAdminError("Google Admin pagination exceeded the collection limit.")

    def collect(self, domain: str, customer_id: str) -> dict:
        binding = self.binding(domain, customer_id)
        collections = {}
        for name, path, key, fields in (
            ("users", "users", "users", "nextPageToken,users(id,customerId,isAdmin,isDelegatedAdmin,suspended,archived,isEnrolledIn2Sv,isEnforcedIn2Sv)"),
            ("roles", f"customer/{customer_id}/roles", "items", "nextPageToken,items(roleId,roleName,isSuperAdminRole,isSystemRole)"),
            ("assignments", f"customer/{customer_id}/roleassignments", "items", "nextPageToken,items(roleAssignmentId,roleId,assignedTo,scopeType,orgUnitId)"),
        ):
            try:
                rows = self.pages(path, key, {"customer": customer_id, "maxResults": 200, "viewType": "admin_view", "projection": "full", "fields": fields} if name == "users" else {"maxResults": 200, "fields": fields})
                if name == "users" and any(row.get("customerId") != customer_id for row in rows):
                    raise GoogleAdminError("User inventory did not match the approved customer.")
                normalized = []
                for row in rows:
                    if name == "users":
                        normalized.append({"key": hashlib.sha256((customer_id + ":" + row["id"]).encode()).hexdigest(),
                            **{key: row.get(key) if type(row.get(key)) is bool else None for key in ("isAdmin", "isDelegatedAdmin", "suspended", "archived", "isEnrolledIn2Sv", "isEnforcedIn2Sv")}})
                    elif name == "assignments":
                        if any(not isinstance(row.get(key), str) or not row[key] for key in ("roleId", "assignedTo", "scopeType")):
                            raise GoogleAdminError("Google omitted role assignment scope or identity; coverage is unconfirmed.")
                        normalized.append({"key": row["roleAssignmentId"], "role_id": row.get("roleId"),
                            "assignee_key": hashlib.sha256((customer_id + ":" + str(row.get("assignedTo"))).encode()).hexdigest(), "scope_type": row.get("scopeType"), "ou_id": row.get("orgUnitId")})
                    else:
                        normalized.append({"key": row["roleId"], "name": row["roleName"][:200] if isinstance(row.get("roleName"), str) else None, "super_admin": row.get("isSuperAdminRole") if type(row.get("isSuperAdminRole")) is bool else None})
                collections[name] = {"status": "collected", "complete": True, "rows": sorted(normalized, key=lambda r: r["key"])}
            except GoogleAdminError as exc:
                collections[name] = {"status": "unavailable", "complete": False, "rows": [], "reason": str(exc)}
        return assess(binding, collections)


def refresh_access_token(client_id: str, client_secret: str, refresh_token: str) -> str:
    with GoogleAdminClient("") as client:
        result = client._request("POST", "https://oauth2.googleapis.com/token", data={
            "grant_type": "refresh_token", "client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token})
    validate_scopes(result.get("scope"))
    access = result.get("access_token")
    if not isinstance(access, str) or not access:
        raise GoogleAdminError("Google did not return an audit access token. Reconnect.")
    return access


def revoke(refresh_token: str) -> bool:
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            response = client.post("https://oauth2.googleapis.com/revoke", data={"token": refresh_token})
            return response.status_code == 200
    except httpx.HTTPError:
        return False


def assess(binding: dict, collections: dict) -> dict:
    checks = [{"id": cid, "title": title, "status": "manual_review", "observed": "Effective policy evidence has not been captured.",
               "expected": expected, "rationale": "Review scoped effective settings and business exceptions before changing configuration.",
               "cis_controls": controls, "source": SOURCE, "method": "manual"} for cid, title, controls, expected in CHECKS]
    users = collections.get("users", {})
    roles = collections.get("roles", {})
    assignments = collections.get("assignments", {})
    if users.get("complete"):
        rows = users["rows"]
        checks[0].update(observed=f"{len(rows)} account records collected; lifecycle roster review is required.", method="api_and_manual")
        admins = [u for u in rows if (u["isAdmin"] is True or u["isDelegatedAdmin"] is True) and u["suspended"] is False and u["archived"] is not True]
        unknown_population = any(u["isAdmin"] is None or u["isDelegatedAdmin"] is None or u["suspended"] is None or u["archived"] is None for u in rows)
        failed = sum(u["isEnforcedIn2Sv"] is False or u["isEnrolledIn2Sv"] is False for u in admins)
        unknown = sum(u["isEnforcedIn2Sv"] is None or u["isEnrolledIn2Sv"] is None for u in admins)
        status = "fail" if failed else "manual_review" if unknown or unknown_population or not admins else "pass"
        checks[2].update(status=status, observed=f"{len(admins)} active administrator accounts; {failed} explicitly missing enforcement/enrollment; {unknown} with unknown 2SV fields. Population fields incomplete: {unknown_population}.",
            method="api", source=ADMIN_SOURCE, rationale="Administrator accounts have elevated access; 2SV reduces account-takeover exposure.",
            validation="Recollect enforcement/enrollment and inspect effective OU/group policies, exceptions and phishing-resistant factors. A pass covers the CSP API criterion only.")
    else:
        for idx in (0, 2):
            checks[idx].update(status="unavailable", observed=users.get("reason", "User evidence unavailable."), method="api")
    checks[1].update(method="api_and_manual", source=ADMIN_SOURCE,
        observed=f"Roles: {len(roles.get('rows', [])) if roles.get('complete') else 'unavailable'}; assignments: {len(assignments.get('rows', [])) if assignments.get('complete') else 'unavailable'}. Group-derived privileges and recovery/separation require manual review.")
    counts = {status: sum(c["status"] == status for c in checks) for status in ("pass", "fail", "manual_review", "unavailable", "not_applicable", "error")}
    definitive = counts["pass"] + counts["fail"]
    return {"binding": binding, "collected_at": datetime.now(UTC).isoformat(), "checklist_version": CHECKLIST_VERSION,
        "framework": "CIS Controls v8.1", "benchmark": "Google Workspace Benchmark version/profile pending review",
        "mapping_type": "CSP control-level interpretation; not a CIS attestation", "collections": collections, "checks": checks,
        "summary": {**counts, "applicable": len(checks), "definitive": definitive,
            "coverage_percent": round(100 * definitive / len(checks), 2), "observed_pass_rate": round(100 * counts["pass"] / definitive, 2) if definitive else None}}


def compare(previous: dict | None, current: dict) -> dict:
    compatible = bool(previous and all(previous.get(k) == current.get(k) for k in ("checklist_version", "framework", "benchmark")) and previous.get("binding") == current.get("binding"))
    result = {"baseline": previous is None, "comparable": compatible, "configuration_changes": [], "coverage_changes": [], "baseline_changes": []}
    if previous is None:
        return result
    if not compatible:
        result["baseline_changes"].append("Customer, domain scope or assessment baseline changed; configuration comparison withheld.")
        return result
    for name in ("users", "roles", "assignments"):
        before, after = previous.get("collections", {}).get(name, {}), current.get("collections", {}).get(name, {})
        if before.get("complete") is True and after.get("complete") is True:
            old, new = {r["key"]: r for r in before["rows"]}, {r["key"]: r for r in after["rows"]}
            for key in sorted(old.keys() | new.keys()):
                before_row, after_row = old.get(key), new.get(key)
                if before_row is None or after_row is None:
                    result["configuration_changes"].append({"collection": name, "key": key, "before": before_row, "after": after_row})
                else:
                    for field in sorted(before_row.keys() | after_row.keys()):
                        before_value, after_value = before_row.get(field), after_row.get(field)
                        if before_value != after_value:
                            destination = "coverage_changes" if field != "ou_id" and (before_value is None or after_value is None) else "configuration_changes"
                            result[destination].append({"collection": name, "key": key, "field": field, "before": before_value, "after": after_value})
        elif before.get("complete") != after.get("complete") or before.get("reason") != after.get("reason"):
            result["coverage_changes"].append({"collection": name, "before": before.get("status"), "after": after.get("status")})
    if previous.get("manual_evidence", {}) != current.get("manual_evidence", {}):
        result["baseline_changes"].append("Manual policy evidence was revised; review the recorded source and scope.")
    return result
