"""Render the standardized NmapUI report from original Nmap XML evidence."""

from pathlib import Path
import hashlib
import re

from lxml import etree


ASSETS = Path(__file__).with_name("scanner_report_assets")
MAX_XML_BYTES = 16 * 1024 * 1024


def original_xml_documents(events: list[dict]) -> list[bytes]:
    """Reassemble complete, hash-verified XML evidence from one frozen scan run."""
    groups = {}
    for event in events:
        if event.get("event_name") != "scan_xml_chunk":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("Invalid original XML chunk payload.")
        target, digest = payload.get("target"), payload.get("sha256")
        count, index, size = (payload.get(key) for key in ("chunk_count", "chunk_index", "byte_count"))
        chunk = payload.get("xml")
        if (not isinstance(target, str) or not target or len(target) > 253
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or type(count) is not int or not 1 <= count <= 525
            or type(index) is not int or not 0 <= index < count
            or type(size) is not int or not 0 < size <= MAX_XML_BYTES
            or not isinstance(chunk, str) or not 0 < len(chunk) <= 32000):
            raise ValueError("Invalid original XML chunk metadata.")
        group = groups.setdefault((target, digest), {"count": count, "size": size, "chunks": {}})
        if count != group["count"] or size != group["size"]:
            raise ValueError("Conflicting original XML chunk metadata.")
        previous = group["chunks"].get(index)
        if previous is not None and previous != chunk:
            raise ValueError("Conflicting original XML chunk content.")
        group["chunks"][index] = chunk
    if not groups:
        raise ValueError("This scan has no original Nmap XML evidence for the approved PDF template.")
    documents = []
    total_bytes = 0
    for (_, expected), group in groups.items():
        if len(group["chunks"]) != group["count"]:
            raise ValueError("Original Nmap XML upload is incomplete; no partial report was created.")
        raw = "".join(group["chunks"][index] for index in range(group["count"])).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != group["size"] or digest != expected:
            raise ValueError("Original Nmap XML failed its saved evidence integrity check.")
        total_bytes += len(raw)
        if total_bytes > 64 * 1024 * 1024:
            raise ValueError("Original Nmap XML exceeds the report evidence limit.")
        documents.append(raw)
    return documents


def standardized_scanner_html(xml: bytes) -> str:
    """Apply the approved PDF XSL without network access or XML entity expansion.

    Accept original XML only: parsed observation summaries cannot establish the
    scan coverage, product versions and script evidence this report displays.
    """
    if not isinstance(xml, bytes) or not xml or len(xml) > MAX_XML_BYTES:
        raise ValueError("Nmap XML evidence must contain 1 to 16777216 bytes.")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    try:
        document = etree.fromstring(xml, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise ValueError("Invalid Nmap XML evidence.") from exc
    if document.tag != "nmaprun":
        raise ValueError("Expected original Nmap nmaprun XML evidence.")
    info = document.getroottree().docinfo
    if info.system_url or info.public_id or (
        info.internalDTD is not None and list(info.internalDTD.iterentities())
    ) or any(
        isinstance(node, etree._Entity) for node in document.iter()
    ):
        raise ValueError("Nmap XML evidence must not contain external DTDs or entities.")
    stylesheet = etree.parse(str(ASSETS / "nmap-pdf-olive-legacy.xsl"), parser=parser)
    transform = etree.XSLT(stylesheet, access_control=etree.XSLTAccessControl.DENY_ALL)
    html = str(transform(document))
    replacements = {
        "__NMAPUI_TAILWIND_CSS__": '<style id="nmapui-tailwind-css">'
        + (ASSETS / "tailwind.css").read_text() + "</style>",
        # PDF rendering has JavaScript disabled; retain the stylesheet's runtime
        # placeholder without allowing script or external resource execution.
        "__NMAPUI_REPORT_RUNTIME__": "",
        "__NMAPUI_REPORT_CSP__": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'",
    }
    for marker, value in replacements.items():
        if html.count(marker) != 1:
            raise ValueError(f"Approved report template has an invalid {marker} placeholder.")
        html = html.replace(marker, value, 1)
    return html
