"""Evidence-linked human implementation plan from the original audit timeline."""
import math
from collections import Counter
from typing import Any

PHASES = ("Immediate · 0–2 weeks", "Short term · 2–6 weeks",
          "Medium term · 6–12 weeks", "Long term · 3–6 months")
SCOPE = ("Suggested review windows from the original Meraki implementation plan, not assigned deadlines. "
         "The network administrator must approve owners, changes and maintenance windows. Observations "
         "do not establish cause or compliance. No configuration changes or purchases are performed.")
CATALOG = {
    "findings": (0, "Review saved network findings", "Confirm each observation against approved security policy and document accepted exceptions or a change plan.", "Recollect settings after an approved change; confirm the observation and intended access policy."),
    "ports": (0, "Investigate switch port observations", "Inspect the reported port, cabling, optics and negotiated link state; distinguish expected idle ports from active link problems.", "Check the intended speed/duplex and diagnostics after an approved repair, then compare a new audit."),
    "coverage": (0, "Restore missing audit evidence", "Check API permissions and product support; resolve failed reads or document a coverage exception.", "Repeat the audit and confirm collection status without interpreting missing data as protection disabled."),
    "rf": (1, "Review wireless profile design", "Check client compatibility, RF density and survey evidence before changing minimum rates, steering or channel width. A 20 MHz channel may be intentional.", "Validate roaming, client connectivity and channel measurements before and after any approved RF change."),
    "channels": (1, "Investigate wireless utilization observations", "Review measured bands against a site survey and application requirements; evaluate channel placement and capacity without inferring interference cause.", "Repeat comparable measurements and verify client outcomes after an approved change."),
    "power": (2, "Validate switch PoE capacity", "Compare actual switch power budgets and peak per-port demand with the proposed AP load. Partial energy readings and daily averages do not establish remaining capacity.", "Document power budget, measured peak load and accessory requirements before approving replacement equipment."),
    "configuration": (2, "Review approved switch configuration baseline", "Review VLANs, uplinks, access policies and documented exceptions against the approved network design.", "Validate authorized connectivity and isolation, record change approval, and compare the subsequent configuration snapshot."),
    "refresh": (3, "Validate hardware refresh and purchase design", "Confirm vendor support/EOL dates and Meraki quotes; review UniFi RF, PoE, WAN, VPN, security and redundancy requirements plus accessories and installation.", "Approve a reviewed bill of materials and migration/rollback plan; dated equipment prices alone do not establish equivalence or savings."),
    "segmentation": (3, "Review segmentation and network authentication", "Review guest isolation, VLAN boundaries and 802.1X feasibility with identity owners before selecting a migration plan.", "Record approved policies and validate allowed and blocked traffic with representative clients during an authorized maintenance window."),
}


def build_action_plan(snapshot: dict, purchase_plan: dict) -> dict:
    rows = []
    def records(key):
        value = snapshot.get(key)
        return value if isinstance(value, list) else []
    def add(key, status, observation, refs):
        phase, title, action, verification = CATALOG[key]
        rows.append({"id": key, "phase": phase, "title": title, "status": status,
                     "observation": observation, "action": action, "verification": verification,
                     "evidence_references": refs, "suggested_owner": "Network administrator"})
    findings = [f for f in records("findings") if isinstance(f, dict) and f.get("status") == "Review"]
    if findings:
        add("findings", "review", f"{len(findings)} saved findings require policy or operational review: " +
            "; ".join(str(f.get("title") or "Review observation")[:200] for f in findings[:5]), ["meraki.findings"])
    ports = sum(r["data"].get("review_port_count", 0) for r in records("switch_ports")
                if isinstance(r, dict) and r.get("status") == "complete" and isinstance(r.get("data"), dict)
                and type(r["data"].get("review_port_count")) is int and r["data"]["review_port_count"] >= 0)
    if ports:
        add("ports", "review", f"{ports} ports have saved review prompts; these are not a diagnosis.", ["meraki.switch_ports"])
    controls = [c for c in records("security_controls") if isinstance(c, dict)]
    unavailable = sum(c.get("status") != "complete" or c.get("data") is None for c in controls)
    if unavailable or not controls:
        add("coverage", "evidence_gap", f"{unavailable} returned control/observation reads are unavailable or unsupported." if controls else "No saved control collection is available.", ["meraki.security_controls", "meraki.warnings"])
    notes = []
    for control in controls:
        if control.get("control") != "Wireless RF profiles" or control.get("status") != "complete" or not isinstance(control.get("data"), list):
            continue
        for profile in control["data"]:
            if not isinstance(profile, dict):
                continue
            observations = []
            band = profile.get("apBandSettings")
            if isinstance(band, dict) and band.get("bandSteeringEnabled") is False:
                observations.append("band steering disabled")
            for key, threshold, title in (("twoFourGhzSettings", 11, "2.4 GHz"), ("fiveGhzSettings", 12, "5 GHz")):
                settings = profile.get(key)
                if not isinstance(settings, dict):
                    continue
                rate = settings.get("minBitrate")
                if type(rate) in (int, float) and math.isfinite(rate) and 0 <= rate <= threshold:
                    observations.append(f"{title} minimum bitrate {rate} Mbps")
                if key == "fiveGhzSettings" and settings.get("channelWidth") in (20, "20", "20MHz"):
                    observations.append("5 GHz channel width 20 MHz")
            if observations:
                notes.append(str(control.get("network_name") or "Network")[:200] + " / " +
                             str(profile.get("name") or profile.get("id") or "RF profile")[:200] + ": " + "; ".join(observations))
    if notes:
        add("rf", "planning", f"{len(notes)} profiles have settings for design review. " + " | ".join(notes[:5]), ["meraki.security_controls: Wireless RF profiles"])
    channels = snapshot.get("channel_utilization")
    channel_count = channels["data"].get("review_band_count") if isinstance(channels, dict) and channels.get("status") == "complete" and isinstance(channels.get("data"), dict) else None
    if type(channel_count) is int and channel_count > 0:
        add("channels", "review", f"{channel_count} measured AP bands meet the saved review thresholds.", ["meraki.channel_utilization"])
    power = snapshot.get("switch_power")
    if isinstance(power, list) and power:
        add("power", "planning", f"{len(power)} switch power observations saved; peak demand and rated capacity are not established.", ["meraki.switch_power", "unifi_plan"])
    if any(c.get("control") == "Switch port configuration" for c in controls):
        add("configuration", "planning", "Port settings are captured evidence; approved baseline and intended connectivity require human validation.", ["meraki.switch_ports", "meraki.security_controls: Switch port configuration"])
    add("refresh", "planning", f"{len(purchase_plan.get('scenarios') or [])} saved purchase scenarios. Support dates, replacement quotes and migration approval require external evidence.", ["unifi_plan", "meraki.devices"])
    add("segmentation", "planning", "Saved network settings do not validate all permitted and blocked traffic or enterprise identity requirements.", ["meraki.security_controls", "meraki_cis8"])
    counts = Counter(r["status"] for r in rows)
    return {"schema_version": 1, "scope": SCOPE, "phases": list(PHASES), "rows": rows,
            "summary": {key: counts[key] for key in ("review", "planning", "evidence_gap")}, "collected_at": snapshot.get("collected_at")}


def project_action_plan(value: Any) -> dict | None:
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        return None
    clean, seen = [], set()
    for row in (value.get("rows") if isinstance(value.get("rows"), list) else [])[:len(CATALOG)]:
        key = row.get("id") if isinstance(row, dict) else None
        if not isinstance(key, str) or key not in CATALOG or key in seen:
            continue
        seen.add(key)
        phase, title, action, verification = CATALOG[key]
        status = row.get("status") if row.get("status") in ("review", "planning", "evidence_gap") else "evidence_gap"
        refs = row.get("evidence_references") if isinstance(row.get("evidence_references"), list) else []
        clean.append({"id": key, "phase": phase, "title": title, "status": status, "action": action,
            "verification": verification, "suggested_owner": "Network administrator",
            "observation": row["observation"][:3000] if isinstance(row.get("observation"), str) else "Evidence unavailable.",
            "evidence_references": [r[:200] for r in refs[:5] if isinstance(r, str)]})
    counts = Counter(r["status"] for r in clean)
    return {"schema_version": 1, "scope": SCOPE, "phases": list(PHASES), "rows": clean,
            "summary": {key: counts[key] for key in ("review", "planning", "evidence_gap")},
            "collected_at": value["collected_at"][:80] if isinstance(value.get("collected_at"), str) else None}
