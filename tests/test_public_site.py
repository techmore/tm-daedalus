from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
import unittest
import yaml


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

    def test_marketing_describes_implemented_evidence_features(self):
        home = (SITE / "index.html").read_text(encoding="utf-8")
        self.assertIn("DNS change history and alerts", home)
        self.assertIn("Versioned endpoint checks and audit history", home)
        self.assertNotIn("Domain email enumeration", home)
        self.assertNotIn("CIS v8 level 1, 2, and 3 device audits", home)

    def test_product_overview_explains_current_evidence_and_endpoint_pilot_scope(self):
        overview = (SITE / "daedalus.html").read_text(encoding="utf-8")
        self.assertIn("saved host and port observations", overview)
        self.assertIn("human review decisions and rationale", overview)
        self.assertIn("macOS 26 Tahoe profiles", overview)
        self.assertIn("Unassessed checks stay visible", overview)
        self.assertIn("Live Tahoe validation and trusted client distribution remain in progress", overview)
        self.assertNotIn("ongoing alignment work for current macOS releases", overview)

    def test_overview_describes_independent_domain_roles_and_override_duration(self):
        overview = (SITE / "daedalus.html").read_text(encoding="utf-8")
        for detail in ("a separate role in each", "30-day probation window", "14-day administrator overrides", "requires its administrator's approval", "Approved collaborators start with the user role", "Project status: active pilot"):
            with self.subTest(detail=detail):
                self.assertIn(detail, overview)

    def test_overview_anchor_offset_and_reduced_motion_styles(self):
        overview = (SITE / "daedalus.html").read_text(encoding="utf-8")
        self.assertIn("section[id]{scroll-margin-top:84px}", overview)
        self.assertIn("@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}", overview)

    def test_existing_csp_school_resources_are_preserved(self):
        home = (SITE / "index.html").read_text(encoding="utf-8")
        legacy_directory = SITE / "Chrome_Moysle_googleadmin"
        self.assertIn("/Chrome_Moysle_googleadmin/school-mac-security-roadmap.html", home)
        self.assertTrue((legacy_directory / "school-mac-security-roadmap.html").is_file())
        self.assertTrue((legacy_directory / "school-mac-chrome-goguardian-setup-guide.md").is_file())

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
        configuration = yaml.safe_load(workflow)
        upload_steps = [step for job in configuration["jobs"].values() for step in job["steps"] if step.get("uses", "").startswith("actions/upload-pages-artifact@")]
        self.assertEqual(len(upload_steps), 1)
        self.assertEqual(upload_steps[0]["with"]["path"], "site")
        self.assertFalse((SITE / ".env").exists())
        self.assertFalse((SITE / "data").exists())
        self.assertFalse((SITE / "backups").exists())


if __name__ == "__main__":
    unittest.main()


def test_site_pages_declare_a_favicon_that_exists():
    from pathlib import Path
    site = Path(__file__).resolve().parents[1] / "site"
    for page in ("index.html", "daedalus.html"):
        html = (site / page).read_text()
        assert 'rel="icon"' in html and "favicon.png" in html
    assert (site / "favicon.png").read_bytes().startswith(b"\x89PNG")
    assert (site / "apple-touch-icon.png").exists()
