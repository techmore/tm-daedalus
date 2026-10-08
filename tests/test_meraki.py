import os
import stat
import tempfile
import unittest
from pathlib import Path

import httpx

from daedalus import credential_store
from daedalus.meraki_api import MerakiAPIError, MerakiClient, _aggregate_client_usage, _managed_topology, summarize_wireless_connections, summarize_channel_utilization, compare_meraki_snapshots, redact_meraki_data
from daedalus.reports import build_meraki_security_pdf


class MerakiClientTests(unittest.TestCase):
    def test_wireless_outcomes_preserve_missing_counts_and_reject_duplicate_identity(self):
        raw = [{"serial": "AP1", "connectionStats": {"success": 0, "assoc": True, "auth": -1, "dhcp": 1.5, "dns": 2}, "client": "never-store"},
               {"serial": "OTHER", "connectionStats": {"success": 100}}]
        result = summarize_wireless_connections(raw, {"AP1", "AP2"})
        self.assertEqual(result["observed_counter_totals"], {"dns": 2, "success": 0})
        self.assertEqual(result["missing_device_count"], 1)
        self.assertEqual(result["omitted_device_count"], 1)
        self.assertEqual(result["counter_coverage"], "partial")
        self.assertNotIn("never-store", str(result))
        self.assertNotIn("success_rate", result)
        with self.assertRaises(MerakiAPIError):
            summarize_wireless_connections([raw[0], raw[0]], {"AP1"})
        self.assertEqual(summarize_wireless_connections([], {"AP1"})["observed_counter_totals"], {})

    def test_wireless_outcomes_do_not_emit_configuration_changes(self):
        def snapshot(count):
            return {"organization": {"id": "org-1"}, "security_controls": [{"network_id": "N_1", "control": "Wireless connection outcomes", "status": "complete", "data": {"success": count}}]}
        self.assertEqual(compare_meraki_snapshots(snapshot(1), snapshot(100))["changed_control_count"], 0)

    def test_uses_api_v1_key_header_and_follows_safe_pagination(self):
        seen = []

        def respond(request):
            seen.append(request)
            self.assertEqual(request.headers.get("X-Cisco-Meraki-API-Key"), "read-only-test-key")
            self.assertEqual(request.url.host, "api.meraki.com")
            self.assertTrue(request.url.path.startswith("/api/v1/"))
            if request.url.path == "/api/v1/organizations" and request.url.params.get("startingAfter"):
                return httpx.Response(200, json=[{"id": "org-2", "name": "Second"}])
            if request.url.path == "/api/v1/organizations":
                return httpx.Response(
                    200,
                    json=[{"id": "org-1", "name": "First"}],
                    headers={
                        "Link": '<https://api.meraki.com/api/v1/organizations?perPage=1000&startingAfter=org-1>; rel="next"'
                    },
                )
            return httpx.Response(404, json={"message": "unexpected request"})

        with MerakiClient(
            "read-only-test-key",
            transport=httpx.MockTransport(respond),
            request_interval=0,
        ) as client:
            organizations = client.list_organizations()

        self.assertEqual(organizations, [
            {"id": "org-1", "name": "First"},
            {"id": "org-2", "name": "Second"},
        ])
        self.assertEqual(len(seen), 2)

    def test_blocks_pagination_to_a_different_host(self):
        def respond(_request):
            return httpx.Response(
                200,
                json=[{"id": "org-1", "name": "First"}],
                headers={"Link": '<https://attacker.invalid/api/v1/steal>; rel="next"'},
            )

        with MerakiClient(
            "read-only-test-key",
            transport=httpx.MockTransport(respond),
            request_interval=0,
        ) as client:
            with self.assertRaisesRegex(MerakiAPIError, "unsafe pagination"):
                client.list_organizations()

    def test_invalid_inventory_fails_before_partial_report_or_availability_collection(self):
        cases = [None, {}, {"serial": ""}, {"serial": 123},
                 {"serial": "bad/path"}, {"serial": "Q2XX-SAFE"}]
        for invalid in cases:
            with self.subTest(invalid=invalid):
                seen = []
                def respond(request):
                    seen.append(request.url.path)
                    paths = {
                        "/api/v1/organizations": [{"id": "org-1", "name": "Test"}],
                        "/api/v1/organizations/org-1/networks": [],
                        "/api/v1/organizations/org-1/devices": [{"serial": "Q2XX-SAFE", "model": "MX100"}, invalid],
                    }
                    return httpx.Response(200, json=paths.get(request.url.path, []))
                with MerakiClient("fixture-key", transport=httpx.MockTransport(respond), request_interval=0) as client:
                    with self.assertRaisesRegex(MerakiAPIError, "device inventory.*no complete audit"):
                        client.collect_security_report("org-1")
                self.assertFalse(any("availabilities" in path for path in seen))

    def test_invalid_network_inventory_is_not_silently_dropped(self):
        for rows in ([None], [{}], [{"id": 123}], [{"id": "N_1"}, {"id": "N_1"}]):
            with self.subTest(rows=rows):
                def respond(request):
                    value = [{"id": "org-1"}] if request.url.path == "/api/v1/organizations" else rows
                    return httpx.Response(200, json=value)
                with MerakiClient("fixture-key", transport=httpx.MockTransport(respond), request_interval=0) as client:
                    with self.assertRaisesRegex(MerakiAPIError, "network inventory"):
                        client.collect_security_report("org-1")

    def test_collects_read_only_inventory_and_flags_disabled_protection(self):
        def respond(request):
            path = request.url.path
            if path.endswith("/appliance/uplinks/usageHistory"):
                self.assertEqual(request.url.params.get("timespan"), "604800")
                self.assertEqual(request.url.params.get("resolution"), "3600")
            responses = {
                "/api/v1/organizations": [{"id": "org-1", "name": "Pilot Org"}],
                "/api/v1/organizations/org-1/networks": [
                    {"id": "N_1", "name": "HQ", "productTypes": ["appliance"], "tags": ["main"]}
                ],
                "/api/v1/organizations/org-1/devices": [
                    {"name": "Gateway", "serial": "Q2XX-TEST", "model": "MX-test", "networkId": "N_1", "productType": "appliance"}
                ],
                "/api/v1/organizations/org-1/devices/availabilities": [
                    {"serial": "Q2XX-TEST", "status": "offline", "lastReportedAt": "2026-09-29T12:00:00Z"}
                ],
                "/api/v1/organizations/org-1/appliance/uplink/statuses": [
                    {"serial": "Q2XX-TEST", "networkId": "N_1", "uplinks": [{"interface": "wan1", "status": "active", "publicIp": "never-store-this"}]}
                ],
                "/api/v1/networks/N_1/appliance/uplinks/usageHistory": [{"startTime": "2026-10-08T00:00:00Z", "endTime": "2026-10-08T01:00:00Z", "byInterface": [{"interface": "wan1", "sent": 450000000, "received": 0}]}],
                "/api/v1/networks/N_1/appliance/firewall/l3FirewallRules": {"rules": []},
                "/api/v1/networks/N_1/appliance/firewall/l7FirewallRules": {"rules": []},
                "/api/v1/networks/N_1/appliance/security/intrusion": {"mode": "disabled"},
                "/api/v1/networks/N_1/appliance/security/malware": {"mode": "enabled", "password": "never-store-this"},
            }
            if path.endswith("inboundFirewallRules") or path.endswith("contentFiltering"):
                return httpx.Response(404, json={"message": "not available"})
            if path not in responses:
                return httpx.Response(404, json={"message": "not available"})
            return httpx.Response(200, json=responses[path])

        with MerakiClient(
            "read-only-test-key",
            transport=httpx.MockTransport(respond),
            request_interval=0,
        ) as client:
            result = client.collect_security_report("org-1")

        self.assertEqual(result["summary"]["network_count"], 1)
        self.assertEqual(result["summary"]["device_status_counts"], {"offline": 1})
        self.assertTrue(any("Intrusion protection is disabled" in row["title"] for row in result["findings"]))
        self.assertEqual(result["summary"]["security_controls_unavailable"], 0)
        self.assertNotIn("never-store-this", str(result))
        self.assertEqual(len(result["security_controls"]), 11)
        self.assertEqual(result["wan_usage"][0]["status"], "complete")
        self.assertEqual(result["wan_usage"][0]["data"]["interfaces"][0]["directions"]["sent"]["average_mbps"], 1)
        self.assertEqual(result["wan_uplinks"]["data"]["state_counts"], {"active": 1})
        self.assertEqual(result["wan_uplinks"]["data"]["rows"][0]["device_name"], "Gateway")
        self.assertEqual(result["wan_uplinks"]["data"]["rows"][0]["network_name"], "HQ")
        self.assertNotIn("never-store-this", str(result))

    def test_collects_switch_and_wireless_allowlisted_settings_with_partial_coverage(self):
        seen = []
        responses = {
            "/organizations": [{"id": "org-1", "name": "Test"}],
            "/organizations/org-1/networks": [{"id": "N_1", "name": "HQ", "productTypes": ["switch", "wireless"]}],
            "/organizations/org-1/devices": [{"serial": "Q2XX-SW01", "model": "MS-test", "networkId": "N_1"}],
            "/organizations/org-1/devices/availabilities": [],
            "/networks/N_1/wireless/ssids": [{"number": 0, "name": "Guest", "enabled": True, "authMode": "open", "psk": "never-store-psk", "radiusServers": [{"secret": "never-store-radius"}]}],
            "/devices/Q2XX-SW01/switch/ports": [{"portId": "1", "enabled": True, "type": "access", "vlan": 10, "accessPolicyType": "802.1x", "unneeded": "never-store-extra"}],
        }

        def respond(request):
            self.assertEqual(request.method, "GET")
            path = request.url.path.removeprefix("/api/v1")
            seen.append(path)
            if path.endswith("accessPolicies"):
                return httpx.Response(404, json={"message": "unsupported"})
            if path.endswith("/statuses"):
                return httpx.Response(403, json={"message": "permission denied"})
            if path not in responses:
                return httpx.Response(404, json={"message": "unsupported"})
            return httpx.Response(200, json=responses[path])

        with MerakiClient("fixture-key", transport=httpx.MockTransport(respond), request_interval=0) as client:
            result = client.collect_security_report("org-1")
        self.assertEqual(result["summary"]["switch_device_count"], 1)
        self.assertEqual(result["summary"]["wireless_network_count"], 1)
        self.assertEqual(result["summary"]["security_controls_unsupported"], 6)
        self.assertEqual(result["summary"]["security_controls_unavailable"], 1)
        self.assertEqual(result["summary"]["security_controls_collected"], 2)
        self.assertTrue(any("Open SSID" in row["title"] for row in result["findings"]))
        self.assertNotIn("never-store", str(result))
        ports = next(row for row in result["security_controls"] if row["control"] == "Switch port configuration")
        self.assertEqual(ports["device_serial"], "Q2XX-SW01")
        self.assertEqual(ports["data"][0]["vlan"], 10)
        self.assertTrue(all("appliance" not in path for path in seen))

    def test_collects_rf_profiles_assignments_and_license_summary_without_secret_payloads(self):
        responses = {
            "/organizations": [{"id": "org-1", "name": "Test"}],
            "/organizations/org-1/networks": [{"id": "N_1", "name": "HQ", "productTypes": ["wireless"]}],
            "/organizations/org-1/devices": [{"serial": "Q2XX-AP01", "model": "MR-test", "networkId": "N_1"}],
            "/organizations/org-1/devices/availabilities": [],
            "/organizations/org-1/licenses/overview": {"status": "License Expired", "expirationDate": "2026-09-01", "licensedDeviceCounts": {"MR": 3, "bad": {"licenseKey": "never-store"}}, "states": {"expired": {"count": 3, "licenseKeys": ["never-store"]}}, "licenseKey": "never-store"},
            "/networks/N_1/wireless/ssids": [],
            "/networks/N_1/wireless/rfProfiles": [{"id": "rf-1", "name": "Office", "twoFourGhzSettings": {"minPower": 5, "maxPower": 20, "validAutoChannels": [1, 6, 11], "clientIdentifier": "never-store"}, "perSsidSettings": {"0": {"minBitrate": 12, "psk": "never-store"}}, "clientSecret": "never-store"}],
            "/organizations/org-1/wireless/devices/channelUtilization/byDevice": [{"serial": "Q2XX-AP01", "network": {"id": "N_1"}, "byBand": [{"band": "5", "total": {"percentage": 60}, "wifi": {"percentage": 50}, "nonWifi": {"percentage": 10}}]}],
            "/organizations/org-1/clients/overview": {"counts": {"total": 3}, "usage": {"overall": {"total": 30, "downstream": 20, "upstream": 10}}, "mac": "never-store"},
            "/networks/N_1/topology/linkLayer": {"nodes": [{"derivedId": "never-store-managed-id", "root": True, "device": {"serial": "Q2XX-AP01", "name": "never-store-name"}}, {"derivedId": "never-store-client-id", "mac": "never-store-client-mac"}], "links": [{"ends": [{"node": {"derivedId": "never-store-managed-id"}}, {"node": {"derivedId": "never-store-client-id"}}]}]},
            "/networks/N_1/wireless/devices/connectionStats": [{"serial": "Q2XX-AP01", "connectionStats": {"assoc": 1, "auth": 2, "dhcp": 3, "dns": 4, "success": 43}, "mac": "never-store"}],
            "/devices/Q2XX-AP01/wireless/radio/settings": {"serial": "Q2XX-AP01", "rfProfileId": "rf-1", "twoFourGhzSettings": {"channel": 6, "targetPower": 15, "clientIdentifier": "never-store"}},
        }
        def respond(request):
            self.assertEqual(request.method, "GET")
            if request.url.path.endswith(("/clients/overview", "/connectionStats")):
                self.assertEqual(request.url.params.get("timespan"), "86400")
            else:
                self.assertFalse(request.url.params)
            return httpx.Response(200, json=responses[request.url.path.removeprefix("/api/v1")])
        # Organization collections legitimately use pagination parameters.
        def paginated_respond(request):
            if "/organizations" in request.url.path and not request.url.path.endswith("overview"):
                return httpx.Response(200, json=responses[request.url.path.removeprefix("/api/v1")])
            return respond(request)
        with MerakiClient("fixture-key", transport=httpx.MockTransport(paginated_respond), request_interval=0) as client:
            result = client.collect_security_report("org-1")
        self.assertEqual(result["wireless_connections"][0]["data"]["observed_counter_totals"]["success"], 43)
        self.assertEqual(result["client_usage"]["data"]["clients_with_usage_count"], 3)
        self.assertEqual(result["topology"][0]["data"]["omitted_node_count"], 1)
        self.assertEqual(result["topology"][0]["data"]["omitted_link_count"], 1)
        self.assertEqual(result["summary"]["rf_profile_count"], 1)
        self.assertEqual(result["summary"]["rf_assignments_collected"], 1)
        self.assertEqual(result["licensing"]["data"]["licensedDeviceCounts"], {"MR": 3})
        self.assertEqual(result["licensing"]["data"]["states"], {"expired": {"count": 3}})
        self.assertNotIn("never-store", str(result))
        self.assertTrue(any(row["title"] == "Meraki licensing needs review" for row in result["findings"]))
        assignment = next(row for row in result["security_controls"] if row["control"] == "Wireless RF assignment")
        self.assertEqual(assignment["device_serial"], "Q2XX-AP01")
        self.assertEqual(assignment["data"]["rfProfileId"], "rf-1")

    def test_topology_retains_only_managed_inventory_links_and_has_bounded_size(self):
        raw = {"nodes": [
            {"derivedId": "raw-a", "device": {"serial": "Q2XX-A"}, "mac": "never-store"},
            {"derivedId": "raw-b", "device": {"serial": "Q2XX-B"}},
            {"derivedId": "raw-client", "discovered": {"lldp": {"managementAddress": "never-store"}}},
        ], "links": [
            {"ends": [{"node": {"derivedId": "raw-a"}}, {"node": {"derivedId": "raw-b"}}]},
            {"ends": [{"device": {"serial": "Q2XX-B"}}, {"device": {"serial": "Q2XX-A"}}]},
            {"ends": [{"node": {"derivedId": "raw-a"}}, {"node": {"derivedId": "raw-client"}}]},
        ]}
        data = _managed_topology(raw, {"Q2XX-A", "Q2XX-B"})
        self.assertEqual(data["links"], [{"device_serials": ["Q2XX-A", "Q2XX-B"], "link_count": 2}])
        self.assertEqual(data["omitted_node_count"], 1)
        self.assertEqual(data["omitted_link_count"], 1)
        self.assertNotIn("never-store", str(data))
        self.assertNotIn("raw-", str(data))
        with self.assertRaises(MerakiAPIError):
            _managed_topology({"nodes": [{}] * 5001, "links": []}, set())

    def test_client_usage_rejects_invalid_aggregate_evidence(self):
        for invalid in (-1, True, "untrusted", float("inf")):
            with self.subTest(value=invalid), self.assertRaises(MerakiAPIError):
                _aggregate_client_usage({"counts": {"total": 3}, "usage": {"overall": {"total": invalid, "downstream": 0, "upstream": 0}}})

    def test_snapshot_comparison_ignores_keyed_array_order_and_tracks_unavailable_evidence(self):
        before = {
            "organization": {"id": "org-1"},
            "security_controls": [
                {"network_id": "N_1", "control": "Wireless SSID security", "status": "complete", "data": [{"number": 1, "enabled": True}, {"number": 0, "enabled": False}]},
                {"network_id": "N_1", "control": "Intrusion protection", "status": "complete", "data": {"mode": "prevention"}},
                {"network_id": "N_1", "control": "Wireless RF profiles", "status": "complete", "data": [{"id": "rf-2", "name": "Outdoor"}, {"id": "rf-1", "name": "Office"}]},
                {"network_id": "", "control": "Aggregate client usage", "status": "complete", "data": {"clients_with_usage_count": 2, "usage": {"total": 100}}},
            ],
        }
        after = {
            "organization": {"id": "org-1"},
            "security_controls": [
                {"network_id": "N_1", "control": "Wireless SSID security", "status": "complete", "data": [{"number": 0, "enabled": False}, {"number": 1, "enabled": True}]},
                {"network_id": "N_1", "control": "Intrusion protection", "status": "unavailable", "data": None},
                {"network_id": "N_1", "control": "Wireless RF profiles", "status": "complete", "data": [{"id": "rf-1", "name": "Office"}, {"id": "rf-2", "name": "Outdoor"}]},
                {"network_id": "", "control": "Aggregate client usage", "status": "complete", "data": {"clients_with_usage_count": 8, "usage": {"total": 900}}},
            ],
        }
        delta = compare_meraki_snapshots(before, after)
        self.assertEqual(delta["changed_control_count"], 0)
        self.assertEqual(len(delta["coverage_changes"]), 1)
        after["security_controls"][0]["data"][0]["enabled"] = True
        after["security_controls"][0]["data"][0]["psk"] = "never-expose"
        delta = compare_meraki_snapshots(before, after)
        self.assertEqual(delta["changed_control_count"], 1)
        self.assertNotIn("never-expose", str(delta))
        with self.assertRaises(ValueError):
            compare_meraki_snapshots(before, {"organization": {"id": "other"}})

    def test_redacts_nested_api_secret_fields(self):
        cleaned = redact_meraki_data({
            "config": [{"sharedSecret": "one", "wpa_psk": "two", "safe": "value"}],
            "clientSecret": "three", "radiusSecret": "four",
        })

        self.assertEqual(cleaned, {"config": [{"safe": "value"}]})


class MerakiCredentialTests(unittest.TestCase):
    def test_local_key_is_owner_only_and_ciphertext_hides_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            key_path = Path(temporary_directory) / "keys" / "development.key"
            old_path = os.environ.get("DAEDALUS_DEV_ENCRYPTION_KEY_FILE")
            old_key = credential_store.ENCRYPTION_KEY
            old_env = credential_store.APP_ENV
            os.environ["DAEDALUS_DEV_ENCRYPTION_KEY_FILE"] = str(key_path)
            credential_store.ENCRYPTION_KEY = ""
            credential_store.APP_ENV = "development"
            credential_store._fernet.cache_clear()
            try:
                plaintext = "meraki-test-api-key-123456"
                encrypted = credential_store.encrypt_secret(plaintext)
                self.assertNotIn(plaintext, encrypted)
                self.assertEqual(credential_store.decrypt_secret(encrypted), plaintext)
                self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(key_path.parent.stat().st_mode), 0o700)
            finally:
                credential_store._fernet.cache_clear()
                credential_store.ENCRYPTION_KEY = old_key
                credential_store.APP_ENV = old_env
                if old_path is None:
                    os.environ.pop("DAEDALUS_DEV_ENCRYPTION_KEY_FILE", None)
                else:
                    os.environ["DAEDALUS_DEV_ENCRYPTION_KEY_FILE"] = old_path


class MerakiReportTests(unittest.TestCase):
    def test_builds_security_pdf_without_credentials(self):
        report = build_meraki_security_pdf({
            "domain": "example.org",
            "requested_by": "admin@example.org",
            "meraki": {
                "organization": {"id": "org-1", "name": "Pilot Org"},
                "collected_at": "2026-09-29T12:00:00Z",
                "summary": {
                    "network_count": 1,
                    "device_count": 1,
                    "appliance_network_count": 1,
                    "device_status_counts": {"offline": 1},
                    "security_controls_collected": 4,
                    "security_controls_unavailable": 0,
                },
                "networks": [{"id": "N_1", "name": "HQ", "productTypes": ["appliance"], "tags": []}],
                "devices": [{"name": "Gateway", "serial": "Q2XX-TEST", "model": "MX-test", "productType": "appliance", "networkId": "N_1", "status": "offline"}],
                "security_controls": [{"network_name": "HQ", "control": "L3 firewall rules", "status": "complete", "data": {"rules": []}}],
                "findings": [{"status": "Review", "title": "Device offline", "detail": "Check device connectivity."}],
                "warnings": [],
            },
        })

        self.assertTrue(report.startswith(b"%PDF-"))
        self.assertTrue(report.rstrip().endswith(b"%%EOF"))
        self.assertGreater(len(report), 1500)


if __name__ == "__main__":
    unittest.main()
