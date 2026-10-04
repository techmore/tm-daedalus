import unittest

from daedalus.external_checks import (
    MAX_EXTERNAL_ORIGINS,
    _external_resource_inventory, compare_snapshots,
)


class ExternalResourceInventoryTests(unittest.TestCase):
    def test_dependency_attributes_are_counted_without_storing_urls_or_hashes(self):
        html="""<script src="https://cdn.example.net/a.js?secret=private" integrity="private-hash"></script>
        <script src="http://cdn.example.net/b.js" integrity=" "></script>
        <link rel="stylesheet" href="https://styles.example.net/a.css">
        <script src="https://sub.example.com/local.js"></script>
        <link rel="preconnect" href="http://cdn.example.net">
        <img src="http://images.example.net/a.png" integrity="not-applicable">"""
        result=_external_resource_inventory(html,'https://example.com/','example.com')
        observed=result['dependency_observations']
        self.assertEqual(observed['http_reference_count'],3)
        self.assertEqual(observed['script_reference_count'],2)
        self.assertEqual(observed['stylesheet_reference_count'],1)
        self.assertEqual(observed['integrity_declared_reference_count'],1)
        self.assertEqual(observed['integrity_missing_reference_count'],2)
        self.assertFalse(observed['integrity_validated'])
        self.assertNotIn('private',str(result))
        self.assertNotIn('not-applicable',str(result))

    def test_new_dependency_collection_does_not_invent_changes_for_old_or_partial_runs(self):
        first=_external_resource_inventory('<script src="https://cdn.example.net/a.js"></script>','https://example.com/','example.com')
        old={key:value for key,value in first.items() if key!='dependency_observations'}
        self.assertEqual(compare_snapshots(old,first),[])
        current=_external_resource_inventory('<script src="https://cdn.example.net/a.js" integrity="declared"></script>','https://example.com/','example.com')
        paths={path for path,_,_ in compare_snapshots(first,current)}
        self.assertEqual(paths,{'dependency_observations.integrity_declared_reference_count','dependency_observations.integrity_missing_reference_count'})
        current['page_html_truncated']=True
        self.assertFalse(any(path.startswith('dependency_observations') for path,_,_ in compare_snapshots(first,current)))

    def test_dependency_pdf_describes_attribute_counts_without_validation_claim(self):
        from unittest.mock import patch
        from daedalus import reports
        observed=_external_resource_inventory('<script src="https://cdn.example.net/a.js"></script>','https://example.com/','example.com')
        with patch.object(reports,'_paragraph',wraps=reports._paragraph) as paragraphs:
            pdf=reports.build_external_posture_pdf({'domain':'example.com','checks':{'web':{'run':{'status':'completed','snapshot':observed}}}})
        values=[str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b'%PDF-'))
        self.assertIn('Script/style integrity not declared',values)
        self.assertTrue(any('Integrity declarations are not validated' in value for value in values))

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
