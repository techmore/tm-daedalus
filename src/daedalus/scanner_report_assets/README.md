# Standardized NmapUI PDF assets

These files are copied unchanged from the existing NmapUI project:

- `nmap-pdf-olive-legacy.xsl`: the PDF stylesheet selected by `nmapui/paths.py`.
- `tailwind.css`: embedded report styling from `static/css/tailwind.css`.
- `report_runtime.js`: embedded report runtime from `static/js/report_runtime.js`.

The user requires this standardized PDF layout to remain the baseline. Enhance
the approved template rather than substituting a different report layout. Keep
the separate NmapUI web stylesheet out of the PDF rendering path.

These assets alone do not restore hosted rendering. The current managed scan
uploads parsed text observations, whereas this template consumes Nmap XML,
including service, script and scan metadata. Preserve that evidence through
collection and upload before enabling the restored renderer. Do not invent
missing product versions, scan coverage, vulnerability counts or remediation.

Historical PDF artifacts and their saved evidence must remain intact.
