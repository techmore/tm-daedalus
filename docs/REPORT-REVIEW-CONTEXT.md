# Keeping report review stable through saved-history refreshes

The report library and topic report lists reuse unchanged cards instead of clearing every report during a successful read. A new report can appear before the report being reviewed without collapsing its saved evidence or discarding its focused control.

## Review behavior

- Each rendered card tracks the saved job content and the Drive connection/admin presentation used to build it. Unchanged cards keep their actual DOM nodes, expanded disclosures and controls.
- Changed jobs rebuild their metadata, progress and download/actions. A Meraki disclosure is reused when its report ID and saved snapshot URL still match, preserving loaded evidence, expanded nested sections and a pending detail read.
- Reordering preserves focus on the original surviving control. A replaced control is matched by its action in the same report, with the report summary/card as fallback. If the report disappears, focus moves to the fixed **Refresh reports** control, or the list if controls are unavailable.
- The current Meraki assessment is rendered again only when its completed report identity, collection/completion dates or summary changes. New failed attempts do not rebuild an unchanged completed assessment. A removed focused observation control moves to the updated summary.
- Identical report counts do not rewrite the list status. Running progress and completed PDF availability still update when the saved job changes.
- Explicit Drive save failures retain **Retry** feedback through an unchanged history read. A successful save displays **Saved to Drive** even when the provider does not supply an open-in-Drive link; a later saved link uses the normal report action.

These are saved-history reads. They do not start a Meraki audit, scan, purchase or PDF generation. The existing history pager continues to retain loaded older boundaries and shown rows after a failed read.

## Validation and remaining acceptance

`tests/test_report_review_context_ui.py` executes the actual shared renderer with a DOM fixture that models focus loss on removal/reparenting. It checks node reuse, new reports, changed metadata, expanded evidence, matching action focus, removal/empty histories, changed current summaries, Drive presentation/outcomes, all five report topics and running-to-completed progress. Existing history and Meraki read/retry tests exercise their actual callbacks separately.

Final local validation passed 1,381 tests, one skipped and 432 subtests; the release-bundle checks passed four tests. The fixtures do not establish populated desktop/mobile visual or screen-reader acceptance. Changed report metadata still rebuilds most of the card; identity is preserved for unchanged cards and matching Meraki evidence disclosures. No overall customer-readiness or complete provider/Drive operation is claimed.

Approved report templates, frozen report snapshots, historical PDFs and scanner assets are unchanged by the rendering implementation. Production activation and normal authenticated review reads require a separate rollout receipt.
