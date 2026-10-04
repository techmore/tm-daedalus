#!/usr/bin/env python3
"""Build Daedalus CIS macOS 26 profile JSON from a pinned NIST mSCP checkout.

The generated files contain recommendation identifiers and titles only. They
never contain or execute the upstream check commands; the CSP client uses a
small local rule-ID allowlist and reports every other rule as manual.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml


SOURCE_COMMIT = "beceac1d21baf9d924c2780f2e248577435bbfb1"
SOURCE_RELEASE = "Tahoe Guidance Revision 3"
SOURCE_URL = "https://github.com/usnistgov/macos_security/tree/" + SOURCE_COMMIT

# These stable mSCP IDs route to bundled preference, fixed-command, and
# bounded audit filesystem/ACL evidence checks.
# All other rules remain manual until a dedicated local implementation exists.
SUPPORTED_RULE_IDS = {
    "system_settings_system_wide_preferences_configure",
    "os_unlock_active_user_session_disable",
    "os_password_hint_remove",
    "audit_retention_configure",
    "os_internal_apfs_volumes_encrypted",
    "audit_auditd_enabled",
    "system_settings_location_services_menu_enforce",
    "system_settings_softwareupdate_current",
    "os_anti_virus_installed",
    "os_guest_folder_removed",
    "os_nfsd_disable",
    "os_power_nap_disable",
    "system_settings_wake_network_access_disable",
    "os_time_server_enabled",
    "audit_control_owner_configure",
    "audit_control_group_configure",
    "audit_control_mode_configure",
    "audit_files_owner_configure",
    "audit_files_group_configure",
    "audit_files_mode_configure",
    "audit_folder_owner_configure",
    "audit_folder_group_configure",
    "audit_folders_mode_configure",
    "audit_acls_files_configure",
    "audit_acls_folders_configure",
    "audit_control_acls_configure",
    "system_settings_screensaver_timeout_enforce",
    "system_settings_hot_corners_secure",
    "os_on_device_dictation_enforce",
    "system_settings_bluetooth_sharing_disable",
    "system_settings_improve_search_disable",
    "system_settings_improve_siri_dictation_disable",
    "system_settings_time_server_enforce",
    "icloud_sync_disable",
    "os_bonjour_disable",
    "system_settings_content_caching_disable",
    "system_settings_media_sharing_disabled",
    "system_settings_time_machine_auto_backup_enable",
    "system_settings_time_server_configure",
    "system_settings_screensaver_ask_for_password_delay_enforce",
    "os_software_update_deferral",

    "os_config_data_install_enforce",
    "os_mail_summary_disable",
    "os_notes_transcription_disable",
    "os_notes_transcription_summary_disable",
    "os_writing_tools_disable",
    "system_settings_external_intelligence_disable",
    "system_settings_external_intelligence_sign_in_disable",
    "system_settings_personalized_advertising_disable",
    "system_settings_improve_assistive_voice_disable",
    "system_settings_loginwindow_prompt_username_password_enforce",

    "os_sip_enable",
    "os_authenticated_root_enable",
    "os_mobile_file_integrity_enable",
    "os_root_disable",
    "system_settings_filevault_enforce",
    "system_settings_printer_sharing_disable",
    "system_settings_remote_management_disable",
    "system_settings_smbd_disable",
    "system_settings_rae_disable",
    "system_settings_screen_sharing_disable",
    "system_settings_ssh_disable",
    "os_tftpd_disable",
    "os_uucp_disable",
    "os_httpd_disable",

    "os_airdrop_disable",
    "os_gatekeeper_enable",
    "os_terminal_secure_keyboard_enable",
    "os_software_update_app_update_enforce",
    "system_settings_airplay_receiver_disable",
    "system_settings_automatic_login_disable",
    "system_settings_critical_update_install_enforce",
    "system_settings_diagnostics_reports_disable",
    "system_settings_firewall_enable",
    "system_settings_firewall_stealth_mode_enable",
    "system_settings_guest_account_disable",
    "system_settings_install_macos_updates_enforce",
    "system_settings_internet_sharing_disable",
    "system_settings_password_hints_disable",
    "system_settings_screensaver_password_enforce",
    "system_settings_siri_disable",
    "system_settings_software_update_download_enforce",
    "system_settings_guest_access_smb_disable",
    "os_safari_advertising_privacy_protection_enable",
    "os_safari_open_safe_downloads_disable",
    "os_safari_prevent_cross-site_tracking_enable",
    "os_safari_show_full_website_address_enable",
    "os_safari_show_status_bar_enabled",
    "os_safari_warn_fraudulent_website_enable",
}


def benchmark_ids(rule: dict[str, Any]) -> list[str]:
    cis = ((rule.get("references") or {}).get("cis") or {}).get("benchmark") or []
    if isinstance(cis, str):
        cis = [cis]
    result: list[str] = []
    for value in cis:
        match = re.match(r"\s*([0-9]+(?:\.[0-9]+)*)\s*(?:\(|$)", str(value))
        if match and match.group(1) not in result:
            result.append(match.group(1))
    return result


def load_profile(source_root: Path, level: int) -> dict[str, Any]:
    baseline_path = source_root / "baselines" / f"cis_lvl{level}.yaml"
    baseline = yaml.safe_load(baseline_path.read_text(encoding="utf-8"))
    checks: list[dict[str, Any]] = []
    for section in baseline["profile"]:
        for rule_id in section["rules"]:
            rule_path = next((source_root / "rules").rglob(f"{rule_id}.yaml"), None)
            if rule_path is None:
                raise ValueError(f"Pinned mSCP source is missing rule {rule_id}.")
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
            check = {
                "id": rule_id,
                "rule_id": rule_id,
                "category": "macos",
                "description": str(rule.get("title") or rule_id)[:500],
                "benchmark_ids": benchmark_ids(rule),
            }
            checks.append(check)

    title = f"CIS Apple macOS 26 Tahoe Benchmark v1.1.0 — Level {level}"
    return {
        "slug": f"cis-macos-26-tahoe-level-{level}",
        "name": title,
        "version": "1.1.0-r2",
        "platform": "macos",
        "description": (
            f"{len(checks)} rules from the pinned NIST mSCP baseline. The installed client implements "
            "a documented subset as bundled read-only checks and reports unsupported rules as manual. "
            "Check coverage depends on the client build. The percentage is a pass rate, not a CIS attestation."
        ),
        "benchmark": {
            "name": "CIS Apple macOS 26.0 Tahoe Benchmark",
            "version": "1.1.0",
            "level": str(level),
            "os_version": "26.0",
            "source": "NIST macOS Security Compliance Project (mSCP)",
            "source_release": SOURCE_RELEASE,
            "source_commit": SOURCE_COMMIT,
            "source_url": f"{SOURCE_URL}/baselines/cis_lvl{level}.yaml",
            "license": "CC BY 4.0",
            "attribution": "NIST macOS Security Compliance Project; derived from its CIS Level baseline.",
            "disclaimer": "CIS and NIST do not endorse Daedalus or the CSP client.",
        },
        "checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mscp-root", required=True, type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src" / "daedalus" / "profiles",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for level in (1, 2):
        profile = load_profile(args.mscp_root, level)
        destination = args.output_dir / f"cis-macos-26-tahoe-level-{level}.json"
        destination.write_text(
            json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Wrote {destination} ({len(profile['checks'])} checks)")


if __name__ == "__main__":
    main()
