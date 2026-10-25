# Historical NmapUI PDF assets — baseline acceptance pending

The corrective source candidate uses `nmap-pdf-olive-approved.xsl`, copied unchanged
from NmapUI commit `86e404fc16626c9c674d52663101600ad29de695`. Its SHA-256 is
`687e6ff1522e99a77ba03ddfe367fd098c7eb0c57eb231f3aa370fcf5ad31537`.
Its generated HTML exactly matches the saved August 22 seven-page example
after serializer whitespace normalization. External CSS/font loading is replaced
in the generated head only; the historical body and inline styles are preserved.
Bundled utility colors are mapped back to that template's original olive palette.
The later `nmap-pdf-olive-legacy.xsl` is retained as source provenance, not selected
by the corrective source candidate. Neither filename establishes human approval.
The exact standardized reference and full visual parity remain unverified.

These files retain the bytes verified against NmapUI source `ead498812fd3`.
The October 25 engine refresh does not update the hosted report baseline:

- `nmap-pdf-olive-legacy.xsl`: the PDF stylesheet selected by `nmapui/paths.py`.
- `tailwind.css`: embedded report styling from `static/css/tailwind.css`.
- `report_runtime.js`: embedded report runtime from `static/js/report_runtime.js`.
- `fonts/`: locally bundled Inter and Instrument Serif fonts and their licenses.

The frozen legacy XSL SHA-256 is
`84cd911b6a0c2ecd4e6dbb991301afc8b1f956c3b247f156d7a7717d08f133a4`,
Tailwind is `c9f25a1f752e7d51faca479a190657929812107a465e8b24d7866115c838f73d`,
and report runtime is `d03ed605446c229533335a5b8f92dfa47bb12a8b2d0f93d5227360ff9b759318`.
New engine UI styles and legacy-report changes require separate hosted visual
qualification before replacing these bytes or the approved historical template.

The user requires their existing standardized PDF to remain the baseline, with
enhancements only. Identify that exact reference before selecting a production
renderer; the saved historical export alone does not establish approval. Keep
the separate NmapUI web stylesheet out of the PDF rendering path.

Hosted rendering now consumes complete hash-verified original XML chunks. The
scanner captures those alongside its existing parsed observations. The template
requires original service, script and scan metadata. Do not invent
missing product versions, scan coverage, vulnerability counts or remediation.

Visual acceptance remains open: the historical template's stable reproduction
has seven pages, while the later source stylesheet produced eleven pages from
the same XML. Finishing entrance animations prevents capture clipping, and the
historical sections are restored. Typography and table spacing still require
comparison. Do not deploy this renderer as a verified visual match until resolved.

Historical PDF artifacts and their saved evidence must remain intact.
