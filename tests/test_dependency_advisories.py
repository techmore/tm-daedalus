import json

import httpx
import pytest

from daedalus.dependency_advisories import MAX_RESPONSE_BYTES, OSV_BATCH_URL, query_declared_package_advisories


METADATA = {"schema_version": 1, "truncated": False, "packages": [{"ecosystem": "npm", "name": "react", "version": "18.3.1"}]}


def collect(payload, status=200):
    def handler(request):
        assert str(request.url) == OSV_BATCH_URL
        assert request.method == "POST"
        assert json.loads(request.content) == {"queries": [{"package": {"ecosystem": "npm", "name": "react"}, "version": "18.3.1"}]}
        return httpx.Response(status, json=payload)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return query_declared_package_advisories(METADATA, client=client)


def test_advisories_are_sorted_deduplicated_and_not_execution_verdicts():
    result = collect({"results": [{"vulns": [{"id": "GHSA-test-bbbb-cccc"}, {"id": "CVE-2020-1234"}, {"id": "CVE-2020-1234"}]}]})
    assert result["state"] == "observed"
    assert result["packages"][0]["advisory_ids"] == ["CVE-2020-1234", "GHSA-test-bbbb-cccc"]
    assert result["package_bytes_verified"] is False
    assert result["execution_verified"] is False
    assert result["observed_at"]


def test_no_match_requires_valid_successful_response():
    result = collect({"results": [{}]})
    assert result["state"] == "observed"
    assert result["packages"][0]["advisory_ids"] == []


@pytest.mark.parametrize("payload", [{}, {"results": []}, {"results": [None]}, {"results": [{"vulns": None}]}, {"results": [{"vulns": [{"id": "https://evil.test"}]}]}])
def test_malformed_evidence_is_unavailable(payload):
    result = collect(payload)
    assert result["state"] == "unavailable"
    assert result["packages"] == []


def test_pagination_does_not_claim_complete_lookup():
    result = collect({"results": [{"next_page_token": "private-token", "vulns": [{"id": "CVE-2020-1234"}]}]})
    assert result["state"] == "partial"
    assert result["packages"][0]["state"] == "partial"
    assert "private-token" not in str(result)


@pytest.mark.parametrize("token", [False, 0, [], {}, "x" * 4097])
def test_invalid_pagination_cannot_establish_complete_lookup(token):
    result = collect({"results": [{"next_page_token": token}]})
    assert result["state"] == "unavailable"
    assert result["packages"] == []


def test_http_errors_do_not_retain_provider_body_or_follow_redirects():
    result = collect({"private": "must not retain"}, 302)
    assert result["state"] == "unavailable"
    assert result["http_status"] == 302
    assert "must not retain" not in str(result)


def test_no_packages_make_no_provider_request():
    def handler(request):
        pytest.fail("No network request should occur")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert query_declared_package_advisories({"schema_version": 1, "packages": []}, client=client)["state"] == "not_assessed"
        invalid = {"schema_version": 1, "packages": [{"ecosystem": "npm", "name": "react", "version": "latest"}]}
        assert query_declared_package_advisories(invalid, client=client)["state"] == "not_assessed"


def test_response_size_is_bounded():
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)))) as client:
        assert query_declared_package_advisories(METADATA, client=client)["state"] == "unavailable"


def test_transport_failure_is_not_zero_advisories():
    def handler(request):
        raise httpx.ReadTimeout("private failure detail", request=request)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = query_declared_package_advisories(METADATA, client=client)
    assert result["state"] == "unavailable"
    assert result["packages"] == []
    assert "private failure detail" not in str(result)
