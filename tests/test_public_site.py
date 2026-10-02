from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
import unittest


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


class SiteParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.references = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if value := attributes.get("id"):
            self.ids.add(value)
        for name in ("href", "src"):
            value = attributes.get(name)
            if value:
                self.references.append(value)


class PublicSiteTests(unittest.TestCase):
    def test_pages_entrypoints_exist_and_link_to_each_other(self):
        home = (SITE / "index.html").read_text(encoding="utf-8")
        overview = (SITE / "daedalus.html").read_text(encoding="utf-8")
        self.assertIn('href="daedalus.html"', home)
        self.assertIn('href="index.html"', overview)
        self.assertIn("https://daedalus.cybersecuritypilot.org/", home)
        self.assertIn("https://daedalus.cybersecuritypilot.org/", overview)

    def test_local_links_and_fragments_resolve(self):
        for page in sorted(SITE.glob("*.html")):
            parser = SiteParser()
            parser.feed(page.read_text(encoding="utf-8"))
            for reference in parser.references:
                parsed = urlsplit(reference)
                if parsed.scheme or parsed.netloc or reference.startswith("//"):
                    continue
                if parsed.path:
                    target = (page.parent / parsed.path).resolve()
                    self.assertTrue(target.is_relative_to(SITE.resolve()), reference)
                    self.assertTrue(target.is_file(), f"{page.name}: missing {reference}")
                if parsed.fragment:
                    self.assertIn(parsed.fragment, parser.ids, f"{page.name}: missing #{parsed.fragment}")

    def test_pages_workflow_publishes_only_the_static_site(self):
        workflow = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
        self.assertIn("path: site", workflow)
        self.assertIn("actions/upload-pages-artifact", workflow)
        self.assertIn("actions/deploy-pages", workflow)


if __name__ == "__main__":
    unittest.main()
