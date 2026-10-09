# Saved evidence refresh

## Customer behavior

DNS/email and website topics lead with the saved assessment and its collection date. **Refresh saved evidence** reloads stored evidence. It does not submit a new audit, change a schedule, authorize a scan or mark an inbox notice read. Administrators use separate run controls to collect new evidence.

Exposure and deeper website reviews have independent refresh controls. If a read fails, the displayed findings, dates, changes and history remain available. The inline status says the previously loaded evidence may be out of date and offers **Retry saved evidence**. It remains visible while retrying and clears only after a complete successful read. A first-load failure displays unavailable evidence rather than an empty successful assessment. No modal or completion toast is added.

## History and freshness contract

- Run and change history have independent keyset boundaries. Refresh stages the first page and re-reads each previously loaded prefix before committing the view.
- If a boundary row has been removed, descending IDs allow reading through its former position. History pages remain bounded to 100 rows per request; review depth follows the pages the user has loaded.
- A failure partway through that refresh retains the entire preceding view. Partial new pages are not mixed with older metadata.
- Older-page reads retain the assessment metadata from the existing view. A full refresh updates assessment metadata and history together. Pages are separate database reads, so this does not promise a single transaction snapshot across concurrent collection.
- Each response must match the check type and domain, contain descending positive row IDs and valid next-page metadata, and provide consistent latest-successful-assessment metadata. Malformed or mismatched responses leave the preceding evidence intact.
- Overlapping reads use a request sequence and an abort signal. Late successes and errors from superseded reads cannot update the view or its status. Background exposure/Nikto polls let an active history request finish.
- A failed/running/cancelled attempt remains visible separately from earlier successful evidence. Nikto and exposure review use the separately returned latest successful snapshot, even when it is outside the visible run page.
- Queue/cancellation/run controls keep their server authorization. A refresh does not establish current workspace control authority or resolve security findings.

## Review context and accessibility

Retry controls retain keyboard focus while busy. `aria-disabled` and `aria-busy` communicate the pending read; handlers refuse duplicate older-page requests. If the last older-history page hides its control, focus moves to the corresponding refresh button.

Nikto run disclosures preserve their open state. A focused queued-run cancellation action is restored if it still exists; otherwise focus moves to saved-evidence refresh. Failed reads preserve the existing DOM. Status text uses literal text, updates only when changed and avoids repeated healthy background-loading announcements.

## Validation and remaining acceptance

Actual Node execution covers the shared pager, all four dashboard bindings, independent boundaries, partial failures, malformed/domain-mismatched pages, late success/error suppression, first-load failure, retry warning persistence, background concurrency, expanded Nikto details, latest successful evidence outside a page and keyboard transitions. Authenticated route/report and broader application fixtures exercise the surrounding source contracts.

These fixtures do not establish populated desktop/mobile visual or screen-reader acceptance. That review remains required for the whole portal, alongside real customer-domain/access, fleet, CIS distribution, Google Admin and operating recovery acceptance.
