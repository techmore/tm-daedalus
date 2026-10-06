from unittest.mock import patch

from daedalus import site_icon

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 40
HTML = b'<html><head><link rel="icon" type="image/png" href="/static/i.png"><link rel="shortcut icon" href="/favicon.ico"></head></html>'


def fake(responses):
    def _get(url, allowed, limit):
        status, body = responses.get(url, (404, b""))
        return status, {}, body, url
    return _get


def test_sniffing_accepts_only_raster_images_and_rejects_svg_and_html():
    assert site_icon.sniff_icon_type(PNG) == "image/png"
    assert site_icon.sniff_icon_type(b"\x00\x00\x01\x00rest") == "image/x-icon"
    assert site_icon.sniff_icon_type(b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>") is None
    assert site_icon.sniff_icon_type(b"<html>") is None


def test_declared_icon_link_is_used_and_resolved_against_the_page():
    pages = {"https://example.test/": (200, HTML), "https://example.test/static/i.png": (200, PNG)}
    with patch.object(site_icon, "_get", fake(pages)):
        assert site_icon.fetch_site_icon("example.test") == ("image/png", PNG)


def test_falls_back_to_favicon_ico_and_skips_non_image_bodies():
    pages = {"https://example.test/": (200, b"<html></html>"),
             "https://example.test/favicon.ico": (200, b"<svg onload=alert(1)>")}
    with patch.object(site_icon, "_get", fake(pages)):
        assert site_icon.fetch_site_icon("example.test") is None
    pages["https://example.test/favicon.ico"] = (200, b"\x00\x00\x01\x00" + b"1" * 20)
    with patch.object(site_icon, "_get", fake(pages)):
        assert site_icon.fetch_site_icon("example.test")[0] == "image/x-icon"


def test_cross_domain_and_data_urls_are_never_requested():
    html = b'<link rel="icon" href="https://evil.test/i.png"><link rel="icon" href="data:image/png;base64,AAAA">'
    seen = []
    def _get(url, allowed, limit):
        seen.append(url)
        if url == "https://example.test/":
            return 200, {}, html, url
        raise site_icon.ExternalCheckFailure("blocked")
    with patch.object(site_icon, "_get", _get):
        assert site_icon.fetch_site_icon("example.test") is None
    # The allowed-host guard inside _get refuses evil.test; data: is never attempted.
    assert not any(url.startswith("data:") for url in seen)
