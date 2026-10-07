"""Save finished report PDFs into a Google Drive folder.

Uses the least-privilege drive.file scope, so Daedalus can only see files and
folders it created. Only fixed Google hosts are contacted.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
import uuid

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
FILES_URL = "https://www.googleapis.com/drive/v3/files"
UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink"
MAX_RESPONSE_BYTES = 256 * 1024
MAX_UPLOAD_BYTES = 64 * 1024 * 1024


class DriveError(Exception):
    """A Drive call failed; the message is safe to show to the workspace admin."""


def _call(request: urllib.request.Request) -> dict:
    host = urllib.parse.urlparse(request.full_url).hostname
    if host not in {"oauth2.googleapis.com", "www.googleapis.com"}:
        raise DriveError("Refused to contact an unexpected host.")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed Google hosts only
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read(4096) or b"{}").get("error_description") or ""
        except (ValueError, AttributeError):
            pass
        raise DriveError(f"Google Drive returned HTTP {exc.code}. {detail}".strip()) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DriveError("Google Drive could not be reached.") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise DriveError("Google Drive sent an unexpectedly large response.")
    try:
        return json.loads(raw or b"{}")
    except ValueError as exc:
        raise DriveError("Google Drive sent an unreadable response.") from exc


def refresh_access_token(client_id: str, client_secret: str, refresh_token: str) -> str:
    body = urllib.parse.urlencode({
        "client_id": client_id, "client_secret": client_secret,
        "refresh_token": refresh_token, "grant_type": "refresh_token",
    }).encode()
    result = _call(urllib.request.Request(TOKEN_URL, data=body, method="POST",
                                          headers={"Content-Type": "application/x-www-form-urlencoded"}))
    token = result.get("access_token")
    if not isinstance(token, str) or not token:
        raise DriveError("Google did not return an access token. Reconnect Google Drive.")
    return token


def create_folder(access_token: str, name: str) -> str:
    payload = json.dumps({"name": name[:200], "mimeType": "application/vnd.google-apps.folder"}).encode()
    result = _call(urllib.request.Request(FILES_URL + "?fields=id", data=payload, method="POST", headers={
        "Authorization": "Bearer " + access_token, "Content-Type": "application/json"}))
    folder_id = result.get("id")
    if not isinstance(folder_id, str) or not folder_id:
        raise DriveError("Google Drive did not create the folder.")
    return folder_id


def upload_pdf(access_token: str, folder_id: str, file_name: str, data: bytes) -> dict:
    if len(data) > MAX_UPLOAD_BYTES:
        raise DriveError("The report is too large to upload.")
    boundary = "daedalus-" + uuid.uuid4().hex
    metadata = json.dumps({"name": file_name[:200], "parents": [folder_id], "mimeType": "application/pdf"}).encode()
    body = (f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode() + metadata
            + f"\r\n--{boundary}\r\nContent-Type: application/pdf\r\n\r\n".encode() + data
            + f"\r\n--{boundary}--".encode())
    result = _call(urllib.request.Request(UPLOAD_URL, data=body, method="POST", headers={
        "Authorization": "Bearer " + access_token,
        "Content-Type": f"multipart/related; boundary={boundary}"}))
    if not isinstance(result.get("id"), str):
        raise DriveError("Google Drive did not confirm the upload.")
    return {"id": result["id"], "name": result.get("name"), "web_view_link": result.get("webViewLink")}


def revoke(token: str) -> None:
    try:
        _call(urllib.request.Request(REVOKE_URL, data=urllib.parse.urlencode({"token": token}).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"}))
    except DriveError:
        pass  # disconnecting locally is what matters; the token may already be invalid
