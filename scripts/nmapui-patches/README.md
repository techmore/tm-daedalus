# Curated NmapUI corrections

`frozen-replay-payloads.patch` records the October 9 correction to the shipped scanner's event snapshots. It applies to the source extracted from ZIP SHA-256 `37a8b078deb94704f4cd334c94f695f48e4e828f79c7292ad504e0e7ca24469c`; its two resulting runtime files exactly match the corrected source ZIP tracked in Daedalus.

For a matching source checkout, review and apply from that checkout's root:

```sh
patch --dry-run -p1 -i /absolute/path/to/frozen-replay-payloads.patch
patch -p1 -i /absolute/path/to/frozen-replay-payloads.patch
```

The maintained sibling NmapUI checkout already includes this correction. Do not apply it twice. Build the distributable source through `scripts/build_nmapui_source_bundle.py`, review the manifest/source differences and run the packaged-source regression suite. This patch changes event delivery/storage, with no PDF template changes. [Correction and validation](../../docs/SCANNER-LIVE-VALIDATION.md#frozen-event-payload-correction--october-9).
