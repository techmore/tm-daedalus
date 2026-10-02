import json
import unittest
from unittest.mock import patch

from daedalus.active_website_checks import MAX_PROBE_BYTES, PROBE_PATHS, _fetch, _signature, run_active_website_check
from daedalus.external_checks import ExternalCheckFailure


class Response:
    def __init__(self, body=b"", status=200, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}

    def getheader(self, key):
        return self.headers.get(key)

    def read(self, limit):
        assert limit == MAX_PROBE_BYTES + 1
        return self.body[:limit]


class Connection:
    def __init__(self, response):
        self.response, self.sock, self.closed, self.requests = response, None, False, []

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self):
        self.closed = True


class ActiveWebsiteTests(unittest.TestCase):
    def collect(self, responses):
        connections = [Connection(response) for response in responses]
        with patch("daedalus.active_website_checks._public_addresses", return_value=["8.8.8.8", "1.1.1.1"]) as resolve, patch("daedalus.active_website_checks._ExposureHTTPSConnection", side_effect=connections) as connect:
            result = run_active_website_check("EXAMPLE.TEST.")
        resolve.assert_called_once_with("example.test")
        self.assertEqual(connect.call_count, 6)
        for call in connect.call_args_list:
            self.assertEqual(call.args, ("example.test", "8.8.8.8"))
            self.assertGreater(call.kwargs["timeout"], 0)
            self.assertLessEqual(call.kwargs["timeout"], 5)
        self.assertTrue(all(connection.closed for connection in connections))
        self.assertEqual([connection.requests[0][1] for connection in connections[1:]], list(PROBE_PATHS))
        self.assertRegex(connections[0].requests[0][1], r"^/\.daedalus-missing-[a-f0-9]{32}$")
        return result

    def test_signatures_and_secret_contents_never_persist(self):
        secret = "NEVER-PERSIST-THIS-SECRET"
        result = self.collect([
            Response(b"not found", 404), Response(b"ref: refs/heads/main\n"),
            Response(b"[core]\nrepositoryformatversion = 0\n[remote]\nurl=https://user:PRIVATE@host\n"),
            Response(f"APP_ENV=production\nAPI_KEY={secret}\n".encode()),
            Response(b"Apache Server Status for example\nServer Version: Apache\n"),
            Response(b"PHP Version 8.4 phpinfo() Configuration PHP Variables"),
        ])
        self.assertTrue(result["coverage_complete"])
        self.assertEqual(len(result["findings"]), 5)
        encoded = json.dumps(result)
        for value in (secret, "PRIVATE", "refs/heads/main", "API_KEY", "PHP Version 8.4"):
            self.assertNotIn(value, encoded)

    def test_missing_paths_are_observations_not_clean_score(self):
        result = self.collect([Response(b"not found", 404)] * 6)
        self.assertTrue(result["coverage_complete"])
        self.assertEqual(result["findings"], [])
        self.assertTrue(all(probe["assessment"] == "missing_response_observed" for probe in result["probes"]))

    def test_soft404_baseline_blocks_findings_and_resolution(self):
        result = self.collect([Response(b"custom not found", 200)] + [Response(b"ref: refs/heads/main")] * 5)
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["baseline"]["assessment"], "soft_404_unknown")

    def test_baseline_matching_200_is_not_complete_coverage(self):
        result = self.collect([Response(b"ref: refs/heads/main", 404)] + [Response(b"ref: refs/heads/main")] * 5)
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["findings"], [])
        self.assertTrue(all(probe["assessment"] == "baseline_matching_response" for probe in result["probes"]))

    def test_incomplete_redirect_encoding_failure_status_are_unassessed(self):
        result = self.collect([
            Response(b"not found", 404), Response(headers={"Location": "https://127.0.0.1/"}, status=302),
            Response(b"x" * (MAX_PROBE_BYTES + 1)), Response(headers={"Content-Encoding": "gzip"}),
            Response(status=503), Response(headers={"Content-Length": "100"}),
        ])
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["findings"], [])
        self.assertEqual([p["error_code"] for p in result["probes"]], ["redirect_not_followed", "incomplete_response", "encoded_response", "http_unassessed", "incomplete_response"])
        self.assertNotIn("127.0.0.1", json.dumps(result))

    def test_empty_missing_page_baseline_still_detects_empty_soft_404(self):
        result = self.collect([Response(b"", 404)] + [Response(b"", 200)] * 5)
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["findings"], [])
        self.assertEqual({probe["assessment"] for probe in result["probes"]}, {"baseline_matching_response"})

    def test_public_address_validation_fails_closed(self):
        with patch("daedalus.active_website_checks._public_addresses", side_effect=ExternalCheckFailure("private secret details")), patch("daedalus.active_website_checks._ExposureHTTPSConnection") as connect:
            result = run_active_website_check("example.test")
        connect.assert_not_called()
        self.assertEqual(result["error_code"], "public_address_validation_failed")
        self.assertNotIn("secret", json.dumps(result))

    def test_transport_error_does_not_save_error_content(self):
        result = self.collect([Response(b"not found", 404)] + [OSError("PRIVATE-ERROR")] * 5)
        self.assertFalse(result["coverage_complete"])
        self.assertNotIn("PRIVATE-ERROR", json.dumps(result))

    def test_expired_overall_deadline_never_connects(self):
        with patch("daedalus.active_website_checks._ExposureHTTPSConnection") as connect:
            evidence, body = _fetch("example.test", "8.8.8.8", "/.env", 0)
        connect.assert_not_called()
        self.assertEqual(evidence["error_code"], "overall_deadline")
        self.assertEqual(body, b"")

    def test_request_deadline_is_incomplete(self):
        connection = Connection(Response(b"ref: refs/heads/main"))

        class ImmediateTimer:
            def __init__(self, interval, callback):
                self.callback = callback
            def start(self):
                self.callback()
            def cancel(self):
                pass

        with patch("daedalus.active_website_checks.threading.Timer", ImmediateTimer), patch("daedalus.active_website_checks._ExposureHTTPSConnection", return_value=connection):
            evidence, body = _fetch("example.test", "8.8.8.8", "/.git/HEAD", 5)
        self.assertEqual(evidence["error_code"], "request_deadline")
        self.assertEqual(evidence["assessment"], "unassessed")
        self.assertEqual(body, b"")
        self.assertTrue(connection.closed)
        self.assertEqual(connection.requests, [])

    def test_signature_false_positive_controls(self):
        self.assertIsNone(_signature("/.env", b"<html>API_KEY=example\nAPP_ENV=prod</html>"))
        self.assertIsNone(_signature("/.git/config", b"[core]"))
        self.assertIsNone(_signature("/phpinfo.php", b"Our tutorial mentions PHP Version"))
        self.assertIsNone(_signature("/server-status", b"Apache Server Status for tutorial"))


if __name__ == "__main__":
    unittest.main()
