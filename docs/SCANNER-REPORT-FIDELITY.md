# Scanner report fidelity

## October 8 print layout enhancement

New scanner PDF jobs pin print layout version 1 and its CSS SHA-256 in the saved report snapshot and request audit record. The enhancement wraps command evidence and long CPE/URL values, repeats table headers across pages, and reduces excess print spacing. A zero-width host-state segment is hidden while the numerical Hosts Down metric remains present. The original XSL, fonts, colors, sections, labels and XML evidence are preserved. Reports without print provenance retain their prior rendering; unknown versions or hashes fail instead of substituting another layout.

The actual frozen production report 43 evidence was rendered and visually inspected across all five candidate pages. Command/CPE evidence is visible and the final page contains scan rows plus the original footer. This is a layout review of one real IPv4 loopback scan, not acceptance of an unidentified historical approved template or broad IPv6/multi-host layout validation. Private artifacts remain under validation/scanner-print-layout-20261008/. No historical stored PDF is rewritten.
