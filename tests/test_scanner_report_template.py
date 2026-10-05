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


def test_approved_template_renders_original_evidence():
    html = standardized_scanner_html(XML)
    assert "127.0.0.1" in html
    assert "Example service" in html
    assert "1.2" in html
    assert 'id="nmapui-tailwind-css"' in html
    assert "__NMAPUI_" not in html
    assert "Saved phase history" not in html


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
    assert "127.0.0.1, 127.0.0.2" in html
    assert "nmap -sV 127.0.0.1" in html
    assert "nmap -sV 127.0.0.2" in html


def test_template_evidence_error_becomes_a_readable_validation_failure(monkeypatch):
    from daedalus import scanner_report_template as module
    def fail(document):
        raise module.etree.XSLTApplyError("fixture transform failure")
    monkeypatch.setattr(module.etree, "XSLT", lambda *args, **kwargs: fail)
    with pytest.raises(ValueError, match="could not be rendered"):
        standardized_scanner_html(XML)


def test_pdf_capture_finishes_template_animations_before_printing(monkeypatch):
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
    pdf = module.render_standardized_scanner_pdf({"scanner": {"events": []}})
    assert observed and pdf.startswith(b"%PDF-")
