"""Render the standardized NmapUI report from original Nmap XML evidence."""

from pathlib import Path
import hashlib
import re
import copy
import base64
import os
import sys
import io

from lxml import etree


ASSETS = Path(__file__).with_name("scanner_report_assets")
MAX_XML_BYTES = 16 * 1024 * 1024
APPROVED_TEMPLATE_SHA256 = "687e6ff1522e99a77ba03ddfe367fd098c7eb0c57eb231f3aa370fcf5ad31537"
REPORT_ASSET_SHA256 = {
    "tailwind.css": "c9f25a1f752e7d51faca479a190657929812107a465e8b24d7866115c838f73d",
    "fonts/inter-latin-opsz-normal.woff2": "2c295d99e26dcf357d4d01bcf270fd6924b600c9a13dd8c363ef114f4c6976fa",
    "fonts/instrument-serif-latin-400-normal.woff2": "5eb09b5ac0e28b67c2f041c8ba6d244604ca0c0980d65912ab2d47fed84ddc31",
}


def _report_asset_bytes(name: str) -> bytes:
    data = (ASSETS / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != REPORT_ASSET_SHA256[name]:
        raise ValueError("Scanner PDF styling asset differs from the pinned rendering baseline; report generation stopped.")
    return data


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


def standardized_scanner_html(xml: bytes, *, target_label: str | None = None) -> str:
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
    counts = document.find("runstats/hosts")
    finished = document.find("runstats/finished")
    if counts is None or finished is None or finished.get("exit", "success") != "success":
        raise ValueError("Original Nmap XML has no successful completed scan coverage evidence.")
    try:
        up, down, total = (int(counts.get(key, "")) for key in ("up", "down", "total"))
    except ValueError as exc:
        raise ValueError("Original Nmap XML has invalid host coverage counts.") from exc
    if min(up, down, total) < 0 or up + down != total:
        raise ValueError("Original Nmap XML has inconsistent host coverage counts.")
    template_bytes = (ASSETS / "nmap-pdf-olive-approved.xsl").read_bytes()
    if hashlib.sha256(template_bytes).hexdigest() != APPROVED_TEMPLATE_SHA256:
        raise ValueError("Scanner PDF template differs from the pinned standardized baseline; report generation stopped.")
    stylesheet = etree.parse(io.BytesIO(template_bytes), parser=parser)
    if target_label is not None:
        # Supply the combined scope through the existing target field without
        # changing the standardized stylesheet's layout or its command evidence.
        namespace = {"xsl": "http://www.w3.org/1999/XSL/Transform"}
        for call in stylesheet.xpath("//xsl:call-template[@name='last-command-argument']", namespaces=namespace):
            parameter = call.find("xsl:with-param", namespaces=namespace)
            if parameter is not None and parameter.get("select") == "/nmaprun/@args":
                replacement = etree.Element("{http://www.w3.org/1999/XSL/Transform}text")
                replacement.text = target_label
                replacement.tail = call.tail
                call.getparent().replace(call, replacement)
    transform = etree.XSLT(stylesheet, access_control=etree.XSLTAccessControl.DENY_ALL)
    try:
        html = str(transform(document))
    except etree.XSLTApplyError as exc:
        raise ValueError("Original Nmap XML could not be rendered by the approved template.") from exc
    font_css = ""
    for family, filename, weight in [
        ("Inter", "inter-latin-opsz-normal.woff2", "100 900"),
        ("Instrument Serif", "instrument-serif-latin-400-normal.woff2", "400"),
    ]:
        encoded = base64.b64encode(_report_asset_bytes("fonts/" + filename)).decode("ascii")
        font_css += f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};src:url(data:font/woff2;base64,{encoded}) format('woff2');}}"
    # Preserve the historical stylesheet byte-for-byte. Replace only its
    # external loading mechanisms in the generated head, keeping its body
    # layout, inline styles and report sections intact.
    page = etree.HTML(html)
    head = page.find("head")
    for element in head.xpath("./script|./link"):
        head.remove(element)
    css = _report_asset_bytes("tailwind.css").decode("utf-8")
    shades = ["#f5f6f3", "#e9ebe0", "#d8dbc7", "#bcc2a9", "#979f83", "#777f65",
              "#636b54", "#525845", "#414637", "#32382a", "#25291f"]
    current = ["96% .015", "91% .020", "85% .028", "75% .040", "62% .055", "50% .065",
               "42% .055", "35% .045", "28% .035", "22% .025", "16% .015"]
    for values, color in zip(current, shades):
        css = css.replace(f"oklch({values} 110)", color)
        css = css.replace(f"oklch({values.replace(' .', ' 0.')} 110)", color)
    style = etree.Element("style", id="nmapui-tailwind-css")
    # Current Chromium's table UA font defaults differ from the saved export.
    # Preserve inherited report typography; explicit table utility sizes win.
    style.text = font_css + "table{font-size:inherit;line-height:inherit}" + css
    # The historical CDN appended its generated utility stylesheet after the
    # template's inline styles. Preserve that cascade order locally.
    head.append(style)
    csp = etree.Element("meta", {"http-equiv": "Content-Security-Policy", "content":
        "default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:; base-uri 'none'; form-action 'none'"})
    head.insert(0, csp)
    return etree.tostring(page, method="html", encoding="unicode")


def standardized_scanner_run_html(events: list[dict]) -> str:
    """Merge original host records while retaining their service and script XML."""
    documents = original_xml_documents(events)
    # Validate each document with the same parser and isolation rules before
    # accessing any evidence in it.
    roots = []
    for xml in documents:
        standardized_scanner_html(xml)
        roots.append(etree.fromstring(xml, etree.XMLParser(resolve_entities=False, no_network=True)))
    observed_addresses = {
        address.get("addr") for root in roots for address in root.findall("host/address")
        if address.get("addrtype") in {"ipv4", "ipv6"}
    }
    # A completely missing host upload has no chunk group to mark incomplete.
    # Check the independently saved detailed result records as well.
    required_addresses = set()
    for event in events:
        if event.get("event_name") != "deep_scan_results":
            continue
        payload = event.get("payload")
        hosts = payload.get("hosts") if isinstance(payload, dict) else payload
        if not isinstance(hosts, list) or any(not isinstance(host, dict) for host in hosts):
            raise ValueError("Invalid detailed scan evidence prevents a complete XML report.")
        for host in hosts:
            address = host.get("ip") or host.get("address")
            if not isinstance(address, str) or not address:
                raise ValueError("Detailed scan evidence is missing a host address.")
            required_addresses.add(address)
    if required_addresses - observed_addresses:
        raise ValueError("Original Nmap XML is missing scanned hosts; no partial report was created.")
    if len(roots) == 1:
        return standardized_scanner_html(documents[0])
    if len({root.get("version") for root in roots}) > 1:
        raise ValueError("Original XML uses different Nmap versions; combined report metadata is ambiguous.")
    merged = copy.deepcopy(roots[0])
    for host in list(merged.findall("host")):
        merged.remove(host)
    totals = {key: 0 for key in ("up", "down", "total")}
    seen = set()
    starts, finishes, commands = [], [], []
    for root in roots:
        if root.get("args"):
            commands.append(root.get("args"))
        if root.get("start"):
            starts.append((int(root.get("start")), root.get("startstr", "")))
        finished = root.find("runstats/finished")
        if finished is not None and finished.get("time"):
            finishes.append((int(finished.get("time")), finished.get("timestr", "")))
        counts = root.find("runstats/hosts")
        if counts is None or any(counts.get(key) is None for key in totals):
            raise ValueError("Original XML is missing host coverage counts.")
        for key in totals:
            value = int(counts.get(key))
            if value < 0:
                raise ValueError("Invalid original XML host count.")
            totals[key] += value
        for host in root.findall("host"):
            addresses = tuple(sorted(address.get("addr", "") for address in host.findall("address") if address.get("addrtype") in {"ipv4", "ipv6"}))
            if not addresses or seen.intersection(addresses):
                raise ValueError("Overlapping or unidentified host XML cannot produce an unambiguous combined report.")
            seen.update(addresses)
            merged.insert(len(merged) - 1, copy.deepcopy(host))
    merged.set("args", "\n".join(commands))
    counts = merged.find("runstats/hosts")
    for key, value in totals.items():
        counts.set(key, str(value))
    if starts:
        started, text = min(starts)
        merged.set("start", str(started))
        merged.set("startstr", text)
    if finishes:
        ended, text = max(finishes)
        finished = merged.find("runstats/finished")
        finished.set("time", str(ended))
        finished.set("timestr", text)
        if starts:
            finished.set("elapsed", str(max(0, ended - min(starts)[0])))
    return standardized_scanner_html(etree.tostring(merged), target_label=", ".join(sorted(observed_addresses)))


def render_standardized_scanner_pdf(report_snapshot: dict) -> bytes:
    """Render the approved stylesheet with the same browser print settings as NmapUI."""
    import tempfile
    from playwright.sync_api import sync_playwright

    provenance = report_snapshot.get("scanner_report_template")
    if provenance is not None and (
        not isinstance(provenance, dict)
        or provenance.get("stylesheet_sha256") != APPROVED_TEMPLATE_SHA256
        or ("asset_sha256" in provenance and provenance["asset_sha256"] != REPORT_ASSET_SHA256)
    ):
        raise ValueError("The saved report template no longer matches the standardized baseline; no replacement layout was generated.")

    if sys.platform == "linux" and Path("/opt/daedalus/browser-runtime").is_dir():
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/daedalus/browser-runtime")

    scanner = report_snapshot.get("scanner") or {}
    events = scanner.get("events")
    if not isinstance(events, list):
        raise ValueError("The approved scan PDF requires a saved run with original Nmap XML evidence.")
    html = standardized_scanner_run_html(events)
    with tempfile.TemporaryDirectory(prefix="daedalus-scanner-pdf-") as directory:
        path = Path(directory) / "report.html"
        path.write_text(html, encoding="utf-8")
        with sync_playwright() as playwright:
            # Incus already supplies the container isolation; Chromium still
            # runs as the unprivileged Daedalus service account.
            browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                context = browser.new_context(viewport={"width": 1440, "height": 2160}, java_script_enabled=False, service_workers="block")
                context.route("**/*", lambda route: route.continue_() if route.request.url == path.as_uri() else route.abort())
                page = context.new_page()
                page.set_default_timeout(180000)
                page.emulate_media(media="print")
                page.goto(path.as_uri(), wait_until="networkidle")
                page.evaluate("document.fonts.ready")
                # The existing template animates cards into position. Capture
                # their final state rather than a translated/clipped frame.
                page.evaluate("document.getAnimations().forEach(animation => animation.finish())")
                return page.pdf(format="Letter", print_background=True, prefer_css_page_size=True,
                    margin={"top": "8mm", "right": "8mm", "bottom": "10mm", "left": "8mm"})
            finally:
                browser.close()
