from pathlib import Path

import pytest

from daedalus.scanner_report_template import ASSETS, standardized_scanner_html
from daedalus.scanner_report_template import original_xml_documents
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
