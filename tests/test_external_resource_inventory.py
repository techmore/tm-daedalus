import unittest

from daedalus.external_checks import (
    MAX_EXTERNAL_ORIGINS,
    _external_resource_inventory,
)


class ExternalResourceInventoryTests(unittest.TestCase):
    def test_lists_external_resources_without_storing_full_urls(self):
        html = """
        <html><head>
          <script src="https://www.googletagmanager.com/gtm.js?id=private-token"></script>
          <link rel="stylesheet" href="//fonts.googleapis.com/css?family=Inter">
          <script src="/assets/local.js"></script>
          <script src="https://static.example.com/app.js"></script>
          <img src="data:image/png;base64,ignored">
          <a href="https://checkout.example.net/">ordinary link</a>
        </head></html>
        """

        inventory = _external_resource_inventory(
            html,
            "https://www.example.com/",
            "example.com",
        )

        self.assertEqual(inventory["external_host_count"], 2)
        self.assertEqual(inventory["external_origin_count"], 2)
        self.assertEqual(inventory["external_reference_count"], 2)
        resources = {item["host"]: item for item in inventory["external_resources"]}
        self.assertEqual(resources["www.googletagmanager.com"]["vendor"], "Google Tag Manager")
        self.assertEqual(resources["www.googletagmanager.com"]["category"], "Analytics")
        self.assertEqual(resources["fonts.googleapis.com"]["vendor"], "Google Fonts")
        self.assertEqual(resources["fonts.googleapis.com"]["resource_types"], ["Stylesheet"])
        self.assertNotIn("private-token", str(inventory))
        self.assertNotIn("checkout.example.net", str(inventory))

    def test_flags_plain_http_and_unclassified_hosts(self):
        inventory = _external_resource_inventory(
            '<img src="http://assets.unknown.test/logo.png">',
            "https://example.com/",
            "example.com",
        )

        resource = inventory["external_resources"][0]
        self.assertEqual(resource["scheme"], "http")
        self.assertEqual(resource["vendor"], "Unclassified external host")
        self.assertEqual(resource["category"], "Other")

    def test_caps_origins_but_reports_the_full_observed_count(self):
        html = "".join(
            f'<script src="https://cdn-{index}.example.net/app.js"></script>'
            for index in range(MAX_EXTERNAL_ORIGINS + 1)
        )

        inventory = _external_resource_inventory(
            html,
            "https://example.com/",
            "example.com",
        )

        self.assertEqual(inventory["external_host_count"], MAX_EXTERNAL_ORIGINS + 1)
        self.assertEqual(inventory["external_origin_count"], MAX_EXTERNAL_ORIGINS + 1)
        self.assertEqual(len(inventory["external_resources"]), MAX_EXTERNAL_ORIGINS)
        self.assertTrue(inventory["external_resources_truncated"])


if __name__ == "__main__":
    unittest.main()
