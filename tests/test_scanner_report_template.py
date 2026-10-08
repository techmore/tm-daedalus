from pathlib import Path

import pytest

from daedalus.scanner_report_template import ASSETS, standardized_scanner_html
from daedalus.scanner_report_template import original_xml_documents
from daedalus.scanner_report_template import standardized_scanner_run_html
import hashlib


XML = b'''<?xml version="1.0"?><!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" version="7.98" startstr="2026-10-05">
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="Example service" version="1.2"/></port></ports></host>
<runstats><finished timestr="2026-10-05" elapsed="1"/>
<hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def test_historical_template_renders_original_evidence():
    html = standardized_scanner_html(XML)
    assert "127.0.0.1" in html
    assert "Example service" in html
    assert "1.2" in html
    assert 'id="nmapui-tailwind-css"' in html
    assert "__NMAPUI_" not in html
    assert "Saved phase history" not in html


def test_hosted_report_preserves_original_template_body_exactly():
    from lxml import etree

    # Hosting may replace external asset loaders in the head. It must not
    # rewrite the standardized report's sections, labels, classes or evidence.
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    stylesheet = etree.parse(str(ASSETS / "nmap-pdf-olive-approved.xsl"), parser)
    transform = etree.XSLT(stylesheet, access_control=etree.XSLTAccessControl.DENY_ALL)
    original = etree.HTML(str(transform(etree.fromstring(XML, parser))))
    hosted = etree.HTML(standardized_scanner_html(XML))
    assert etree.tostring(hosted.find("body")) == etree.tostring(original.find("body"))


@pytest.mark.parametrize("xml", [b"", b"<not-nmap/>", b"<broken", b'''<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>''', b'''<!DOCTYPE nmaprun SYSTEM "https://example.com/dtd"><nmaprun/>'''])
def test_invalid_or_external_evidence_is_rejected(xml):
    with pytest.raises(ValueError):
        standardized_scanner_html(xml)


def test_pdf_assets_match_bundled_nmapui_baseline():
    import zipfile

    archive = Path(__file__).resolve().parents[1] / "src/daedalus/agent_bundle/nmapui-source.zip"
    with zipfile.ZipFile(archive) as bundle:
        for source, destination in [
            ("nmap-pdf-olive-legacy.xsl", "nmap-pdf-olive-legacy.xsl"),
            ("static/css/tailwind.css", "tailwind.css"),
            ("static/js/report_runtime.js", "report_runtime.js"),
        ]:
            assert (ASSETS / destination).read_bytes() == bundle.read("daedalus-nmapui-source/" + source)
    assert hashlib.sha256((ASSETS / "nmap-pdf-olive-approved.xsl").read_bytes()).hexdigest() == "687e6ff1522e99a77ba03ddfe367fd098c7eb0c57eb231f3aa370fcf5ad31537"


def xml_events():
    text = XML.decode()
    return [{"event_name": "scan_xml_chunk", "payload": {
        "target": "127.0.0.1", "sha256": hashlib.sha256(XML).hexdigest(),
        "byte_count": len(XML), "chunk_count": 2, "chunk_index": index,
        "xml": chunk,
    }} for index, chunk in enumerate([text[:100], text[100:]])]


def test_xml_chunks_reorder_and_deduplicate_without_changing_evidence():
    events = xml_events()
    assert original_xml_documents([events[1], events[0], events[1]]) == [XML]


def test_missing_or_corrupt_xml_never_produces_partial_evidence():
    with pytest.raises(ValueError, match="incomplete"):
        original_xml_documents(xml_events()[:1])
    events = xml_events()
    events[0]["payload"]["xml"] = "x" * 100
    with pytest.raises(ValueError, match="integrity"):
        original_xml_documents(events)
    with pytest.raises(ValueError, match="no original"):
        original_xml_documents([])


def test_hosted_renderer_requires_original_xml_instead_of_substituting_layout():
    from daedalus.reports import build_scanner_results_pdf
    with pytest.raises(ValueError, match="original Nmap XML"):
        build_scanner_results_pdf({"scanner": {"events": [{"event_name": "deep_scan_results", "payload": [{"ip": "127.0.0.1"}]}]}})


def test_missing_coverage_does_not_render_as_zero_observations():
    with pytest.raises(ValueError, match="coverage"):
        standardized_scanner_html(b"<nmaprun/>")
    with pytest.raises(ValueError, match="inconsistent"):
        standardized_scanner_html(XML.replace(b'up="1" down="0" total="1"', b'up="1" down="0" total="0"'))


def test_completely_missing_host_xml_upload_cannot_silently_omit_host():
    events = xml_events() + [{"event_name": "deep_scan_results", "payload": [
        {"ip": "127.0.0.1"}, {"ip": "127.0.0.2"},
    ]}]
    with pytest.raises(ValueError, match="missing scanned hosts"):
        standardized_scanner_run_html(events)


def test_matching_detail_and_xml_host_evidence_renders():
    events = xml_events() + [{"event_name": "deep_scan_results", "payload": [{"ip": "127.0.0.1"}]}]
    assert "Example service" in standardized_scanner_run_html(events)


def test_combined_xml_target_field_lists_all_hosts_without_losing_commands():
    second = XML.replace(b"127.0.0.1", b"127.0.0.2")
    events = xml_events() + [{"event_name": "scan_xml_chunk", "payload": {
        "target": "127.0.0.2", "sha256": hashlib.sha256(second).hexdigest(),
        "byte_count": len(second), "chunk_count": 1, "chunk_index": 0, "xml": second.decode(),
    }}]
    html = standardized_scanner_run_html(events)
    assert "127.0.0.1" in html and "127.0.0.2" in html
    assert "nmap -sV 127.0.0.1" in html
    assert "nmap -sV 127.0.0.2" in html

def test_combined_xml_rejects_shared_address_with_different_alias_sets():
    aliased = XML.replace(b'<ports>', b'<address addr="::1" addrtype="ipv6"/><ports>')
    events = xml_events() + [{"event_name": "scan_xml_chunk", "payload": {
        "target": "::1", "sha256": hashlib.sha256(aliased).hexdigest(),
        "byte_count": len(aliased), "chunk_count": 1, "chunk_index": 0,
        "xml": aliased.decode(),
    }}]
    with pytest.raises(ValueError, match="Overlapping"):
        standardized_scanner_run_html(events)


def test_template_evidence_error_becomes_a_readable_validation_failure(monkeypatch):
    from daedalus import scanner_report_template as module
    def fail(document):
        raise module.etree.XSLTApplyError("fixture transform failure")
    monkeypatch.setattr(module.etree, "XSLT", lambda *args, **kwargs: fail)
    with pytest.raises(ValueError, match="could not be rendered"):
        standardized_scanner_html(XML)


def test_local_asset_embedding_preserves_entire_historical_report_body():
    from lxml import etree
    historical = etree.XSLT(etree.parse(str(ASSETS / "nmap-pdf-olive-approved.xsl")))(etree.fromstring(XML))
    expected = etree.HTML(str(historical)).find("body")
    actual = etree.HTML(standardized_scanner_html(XML)).find("body")
    assert etree.tostring(actual, method="c14n") == etree.tostring(expected, method="c14n")
    html = standardized_scanner_html(XML)
    head = etree.HTML(html).find("head")
    assert not head.xpath("./script|./link")
    assert "#32382a" in head.xpath("./style[@id='nmapui-tailwind-css']")[0].text
    assert head.findall("style")[-1].get("id") == "nmapui-tailwind-css"


def test_replaced_standardized_template_is_rejected_before_generation(monkeypatch, tmp_path):
    from daedalus import scanner_report_template as module
    replacement = (ASSETS / "nmap-pdf-olive-approved.xsl").read_bytes() + b"\n"
    (tmp_path / "nmap-pdf-olive-approved.xsl").write_bytes(replacement)
    monkeypatch.setattr(module, "ASSETS", tmp_path)
    with pytest.raises(ValueError, match="differs from the pinned standardized baseline"):
        standardized_scanner_html(XML)


@pytest.mark.parametrize("asset", ["tailwind.css", "fonts/inter-latin-opsz-normal.woff2", "fonts/instrument-serif-latin-400-normal.woff2"])
def test_missing_styling_asset_stops_generation_without_fallback(asset, monkeypatch, tmp_path):
    import shutil
    from daedalus import scanner_report_template as module
    shutil.copytree(ASSETS, tmp_path / "assets")
    (tmp_path / "assets" / asset).unlink()
    monkeypatch.setattr(module, "ASSETS", tmp_path / "assets")
    with pytest.raises(ValueError, match="styling asset is unavailable"):
        standardized_scanner_html(XML)


def test_missing_standardized_template_stops_generation_without_fallback(monkeypatch, tmp_path):
    from daedalus import scanner_report_template as module
    monkeypatch.setattr(module, "ASSETS", tmp_path)
    with pytest.raises(ValueError, match="template is unavailable"):
        standardized_scanner_html(XML)


@pytest.mark.parametrize("asset", ["tailwind.css", "fonts/inter-latin-opsz-normal.woff2", "fonts/instrument-serif-latin-400-normal.woff2"])
def test_replaced_styling_asset_is_rejected_without_changing_template(asset, monkeypatch, tmp_path):
    import shutil
    from daedalus import scanner_report_template as module
    shutil.copytree(ASSETS, tmp_path / "assets")
    replacement = tmp_path / "assets" / asset
    replacement.write_bytes(replacement.read_bytes() + b"\n")
    monkeypatch.setattr(module, "ASSETS", tmp_path / "assets")
    with pytest.raises(ValueError, match="styling asset differs from the pinned rendering baseline"):
        standardized_scanner_html(XML)


@pytest.mark.parametrize("provenance", [
    {"stylesheet_sha256": "different-template"}, {}, "invalid",
    {"stylesheet_sha256": "687e6ff1522e99a77ba03ddfe367fd098c7eb0c57eb231f3aa370fcf5ad31537", "asset_sha256": {}},
    {"stylesheet_sha256": "687e6ff1522e99a77ba03ddfe367fd098c7eb0c57eb231f3aa370fcf5ad31537", "asset_sha256": None},
])
def test_queued_report_template_mismatch_cannot_render_a_replacement(provenance, monkeypatch):
    from daedalus import scanner_report_template as module
    def unexpected(events):
        pytest.fail("Mismatched report must stop before preparing another layout")
    monkeypatch.setattr(module, "standardized_scanner_run_html", unexpected)
    with pytest.raises(ValueError, match="saved report template no longer matches"):
        module.render_standardized_scanner_pdf({"scanner_report_template": provenance,
                                              "scanner": {"events": []}})


@pytest.mark.parametrize("include_asset_provenance", [False, True])
def test_pdf_capture_finishes_template_animations_before_printing(monkeypatch, include_asset_provenance):
    from daedalus import scanner_report_template as module
    from playwright.sync_api import Page
    monkeypatch.setattr(module, "standardized_scanner_run_html", lambda events: """<!doctype html>
<style>@keyframes enter {from {transform:translateY(-150px)} to {transform:none}}
.card {animation:enter 100s linear both}</style><div class="card">Original report card</div>""")
    original_pdf = Page.pdf
    observed = []
    def checked_pdf(page, **kwargs):
        states = page.evaluate("document.getAnimations().map(animation => animation.playState)")
        assert states and all(state == "finished" for state in states)
        assert page.evaluate("getComputedStyle(document.querySelector('.card')).transform") in {"none", "matrix(1, 0, 0, 1, 0, 0)"}
        observed.extend(states)
        return original_pdf(page, **kwargs)
    monkeypatch.setattr(Page, "pdf", checked_pdf)
    snapshot = {"scanner": {"events": []}}
    if include_asset_provenance:
        snapshot["scanner_report_template"] = {
            "stylesheet_sha256": module.HISTORICAL_TEMPLATE_SHA256,
            "asset_sha256": dict(module.REPORT_ASSET_SHA256),
        }
    pdf = module.render_standardized_scanner_pdf(snapshot)
    assert observed and pdf.startswith(b"%PDF-")


def test_historical_table_typography_inherits_report_font_in_current_browser(tmp_path):
    from playwright.sync_api import sync_playwright
    path = tmp_path / "report.html"
    path.write_text(standardized_scanner_html(XML))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            page = browser.new_page(java_script_enabled=False)
            page.emulate_media(media="print")
            page.goto(path.as_uri())
            sizes = page.evaluate("""() => ({
                body: getComputedStyle(document.body).fontSize,
                overview: getComputedStyle(document.querySelector('#table-overview')).fontSize,
                service: getComputedStyle(document.querySelector('#table-services')).fontSize
            })""")
            assert sizes["overview"] == sizes["body"]
            assert sizes["service"] == "14px"
        finally:
            browser.close()


def test_changes_panel_matches_nmapui_markup_and_omits_empty_changes():
    from daedalus.scanner_report_template import changes_since_previous_html
    panel = changes_since_previous_html({"baseline": "2026-03-15T14:31:17Z", "counts": {
        "hosts_added": 1, "hosts_removed": 0, "hosts_not_observed": 0,
        "newly_observed_ports": 2, "reported_port_changes": 0, "confirmed_removed_ports": 2}})
    assert 'id="scan-diff-summary"' in panel and "Changes Since Previous Scan" in panel
    assert "Baseline: 2026-03-15T14:31:17Z" in panel
    assert "1 newly observed host(s)" in panel and "2 removed port(s)" in panel
    assert "removed host" not in panel
    zero = {key: 0 for key in ("hosts_added", "hosts_removed", "hosts_not_observed",
            "newly_observed_ports", "reported_port_changes", "confirmed_removed_ports")}
    assert changes_since_previous_html({"counts": zero}) == ""
    assert changes_since_previous_html(None) == ""
    assert "&lt;b&gt;" in changes_since_previous_html({"baseline": "<b>", "counts": {**zero, "hosts_added": 1}})


def test_print_layout_requires_saved_opt_in_and_preserves_body():
    from lxml import etree
    from daedalus.scanner_report_template import (
        scanner_print_layout_html, PRINT_LAYOUT_VERSION, PRINT_LAYOUT_SHA256,
    )
    html = standardized_scanner_html(XML)
    for legacy in (None, {}, {"stylesheet_sha256": "historical"}):
        assert scanner_print_layout_html(html, legacy) == html
    enhanced = scanner_print_layout_html(html, {
        "print_layout_version": PRINT_LAYOUT_VERSION,
        "print_layout_sha256": PRINT_LAYOUT_SHA256,
    })
    assert enhanced.count('id="nmapui-print-layout-v1"') == 1
    assert etree.tostring(etree.HTML(enhanced).find("body")) == etree.tostring(etree.HTML(html).find("body"))
    assert '#web-services td:last-child' in enhanced


@pytest.mark.parametrize("provenance", [
    [], "invalid", {"print_layout_version": True},
    {"print_layout_version": 2, "print_layout_sha256": "wrong"},
    {"print_layout_version": 1}, {"print_layout_sha256": "wrong"},
])
def test_unknown_print_layout_is_never_silently_replaced(provenance):
    from daedalus.scanner_report_template import scanner_print_layout_html
    with pytest.raises(ValueError, match="print layout"):
        scanner_print_layout_html(standardized_scanner_html(XML), provenance)


def test_enhanced_pdf_renders_original_evidence_with_pinned_layout():
    from daedalus.scanner_report_template import (
        render_standardized_scanner_pdf, HISTORICAL_TEMPLATE_SHA256,
        REPORT_ASSET_SHA256, PRINT_LAYOUT_VERSION, PRINT_LAYOUT_SHA256,
    )
    pdf = render_standardized_scanner_pdf({
        "scanner_report_template": {
            "stylesheet_sha256": HISTORICAL_TEMPLATE_SHA256,
            "asset_sha256": dict(REPORT_ASSET_SHA256),
            "print_layout_version": PRINT_LAYOUT_VERSION,
            "print_layout_sha256": PRINT_LAYOUT_SHA256,
        },
        "scanner": {"events": xml_events()},
    })
    assert pdf.startswith(b"%PDF-")
