# Scanner regression and report review — October 12, 2026

## Scope and results

- NmapUI: 698 tests passed, 28 skipped in the default suite; the separately enabled browser group passed all 21 cases.
- Daedalus: 1,581 tests passed, one skipped, 459 subtests; three warnings.
- NmapUI browser regression: 21 passed. Updated obsolete history selectors to exercise the current single-review timeline and automatic previous-compatible-scan comparison. HTML injection checks remain active.
- Added 19 focused scanner cases covering malformed mDNS packets, peer filtering, timeout behavior, LAN gateway preservation under VPN routing, customer/subnet appendix scoping, escaping, repeated appendix insertion, incomplete coverage disclosure and server-authoritative scan customer attribution.
- Existing scanner fixtures were updated for gateway metadata persistence, ARP-specific privilege routing, report customer arguments and the default discovery-only firewall rule.

## Approved PDF template

Generated a baseline and topology-enabled report from retained scanner XML through the existing approved XSL and PDF pipeline. The appendix-enabled document has five pages; the baseline has three. Rendered all five pages and inspected them visually. The first three rendered page images match the baseline byte-for-byte when both use the same print wrapping correction. The only approved-template CSS change wraps long preformatted command text to avoid clipping; report structure is preserved.

Appendix print spacing was tightened to avoid nearly empty continuation pages. Insertion removes both existing appendix sections before replacement. Device identity notes distinguish confirmed from unconfirmed matches. A timed-out host now produces an explicit incomplete-coverage notice: an empty service table cannot establish that ports are closed or vulnerabilities absent. The retained sample's service scan timed out; workflow completion does not certify full service coverage.

Customer XML, PDF, page images and raw soak samples remain private ignored artifacts, outside Git.

## Bounded unattended idle soak

Observed the installed Mac scanner and cloud bridge for 600 seconds, October 12 13:27:52–13:37:52 UTC, at 15-second intervals (41 samples). Every sample showed local responsiveness, no active jobs, cloud online, bridge online, zero pending events and no evidence-preservation failure. No scanner restart occurred during this observation.

This establishes ten minutes of idle stability on one Mac and its current network. It does not establish multi-day operation, scan-load stability, reboot recovery, sleep/wake, roaming or fleet acceptance. Those remain distinct follow-up checks.
