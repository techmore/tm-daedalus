# Standardized NmapUI PDF assets

These files are copied unchanged from the existing NmapUI project:

- `nmap-pdf-olive-legacy.xsl`: the PDF stylesheet selected by `nmapui/paths.py`.
- `tailwind.css`: embedded report styling from `static/css/tailwind.css`.
- `report_runtime.js`: embedded report runtime from `static/js/report_runtime.js`.
- `fonts/`: locally bundled Inter and Instrument Serif fonts and their licenses.

The user requires this standardized PDF layout to remain the baseline. Enhance
the approved template rather than substituting a different report layout. Keep
the separate NmapUI web stylesheet out of the PDF rendering path.

Hosted rendering now consumes complete hash-verified original XML chunks. The
scanner captures those alongside its existing parsed observations. The template
requires original service, script and scan metadata. Do not invent
missing product versions, scan coverage, vulnerability counts or remediation.

Visual acceptance remains open: the saved August 22 loopback PDF is seven pages,
while the current source stylesheet produces eleven pages from the same XML
under print media. Locally embedding the original font families restores the
typography but does not resolve the pagination and section differences. Do not
deploy this renderer as an approved visual match until this discrepancy is resolved.

Historical PDF artifacts and their saved evidence must remain intact.
