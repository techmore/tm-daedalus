import io
import json
import urllib.request
from unittest.mock import patch

import pytest

from daedalus import drive


class FakeResponse(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_only_fixed_google_hosts_are_ever_contacted():
    with pytest.raises(drive.DriveError, match="unexpected host"):
        drive._call(urllib.request.Request("https://evil.example/upload", method="POST"))


def test_upload_builds_multipart_with_folder_parent_and_returns_link():
    seen = {}
    def fake_urlopen(request, timeout):
        seen["url"], seen["body"], seen["headers"] = request.full_url, request.data, dict(request.header_items())
        return FakeResponse(json.dumps({"id": "F1", "name": "r.pdf", "webViewLink": "https://drive.google.com/file/d/F1/view"}).encode())
    with patch.object(drive.urllib.request, "urlopen", fake_urlopen):
        saved = drive.upload_pdf("tok", "FOLDER", "r.pdf", b"%PDF-1.4 body")
    assert saved == {"id": "F1", "name": "r.pdf", "web_view_link": "https://drive.google.com/file/d/F1/view"}
    assert seen["url"].startswith("https://www.googleapis.com/upload/drive/v3/files")
    assert b'"parents": ["FOLDER"]' in seen["body"] and b"%PDF-1.4 body" in seen["body"]
    assert seen["headers"]["Authorization"] == "Bearer tok"


def test_failures_become_safe_messages_and_oversize_is_refused():
    def boom(request, timeout): raise drive.urllib.error.URLError("dns")
    with patch.object(drive.urllib.request, "urlopen", boom):
        with pytest.raises(drive.DriveError, match="could not be reached"):
            drive.refresh_access_token("id", "secret", "refresh")
    with pytest.raises(drive.DriveError, match="too large"):
        drive.upload_pdf("tok", "F", "r.pdf", b"x" * (drive.MAX_UPLOAD_BYTES + 1))


def test_google_error_reason_is_shown_to_the_admin():
    import urllib.error
    body = json.dumps({"error": {"code": 403, "message": "Google Drive API has not been used in project 123 before or it is disabled.",
                                 "errors": [{"reason": "accessNotConfigured"}]}}).encode()
    def forbidden(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(body))
    with patch.object(drive.urllib.request, "urlopen", forbidden):
        with pytest.raises(drive.DriveError) as caught:
            drive.create_folder("tok", "Daedalus Reports")
    assert "HTTP 403" in str(caught.value) and "accessNotConfigured" in str(caught.value) and "disabled" in str(caught.value)
