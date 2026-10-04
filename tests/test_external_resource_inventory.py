import unittest

from daedalus.external_checks import (
    MAX_EXTERNAL_ORIGINS,
    _external_resource_inventory, compare_snapshots,
)


class ExternalResourceInventoryTests(unittest.TestCase):
    def test_per_origin_attributes_identify_dependencies_without_urls_or_hashes(self):
        html = '<script src="https://cdn.example.net/a.js?private=token" integrity="secret-hash"></script><script src="https://cdn.example.net/b.js"></script><link rel="stylesheet" href="http://style.example.net/a.css"><img src="http://style.example.net/a.png">'
        inventory = _external_resource_inventory(html, 'https://example.com/', 'example.com')
        block = inventory['dependency_origin_observations']
        origins = {item['host']: item for item in block['origins']}
        self.assertEqual(origins['cdn.example.net']['script_reference_count'], 2)
        self.assertEqual(origins['cdn.example.net']['integrity_declared_reference_count'], 1)
        self.assertEqual(origins['cdn.example.net']['integrity_missing_reference_count'], 1)
        self.assertEqual(origins['style.example.net']['http_reference_count'], 2)
        self.assertEqual(origins['style.example.net']['stylesheet_reference_count'], 1)
        self.assertEqual(origins['style.example.net']['integrity_missing_reference_count'], 1)
        self.assertFalse(block['integrity_validated'])
        self.assertNotIn('token', str(block))
        self.assertNotIn('secret-hash', str(block))

    def test_origin_collector_upgrade_and_incomplete_evidence_do_not_alert(self):
        import copy
        current = _external_resource_inventory('<script src="https://cdn.example.net/a.js"></script>', 'https://example.com/', 'example.com')
        previous = copy.deepcopy(current); previous.pop('dependency_origin_observations')
        self.assertFalse(compare_snapshots(previous, current))
        changed = copy.deepcopy(current)
        changed['dependency_origin_observations']['origins'][0]['integrity_missing_reference_count'] = 2
        self.assertEqual([path for path, _, _ in compare_snapshots(current, changed)], ['dependency_origin_observations.origins'])
        changed['dependency_origin_observations']['truncated'] = True
        self.assertFalse(compare_snapshots(current, changed))
        changed['dependency_origin_observations']['truncated'] = False
        changed['page_html_truncated'] = True
        self.assertFalse(compare_snapshots(current, changed))

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
        self.assertEqual(paths,{'dependency_observations.integrity_declared_reference_count','dependency_observations.integrity_missing_reference_count','dependency_origin_observations.origins'})
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
        self.assertTrue(any('1 script(s)' in value and '0 declared, 1 not declared' in value for value in values))
        self.assertTrue(any('Integrity declarations are not validated' in value for value in values))

    def test_origin_pdf_evidence_requires_unique_exact_origin_and_typed_counts(self):
        import copy
        from daedalus.reports import _dependency_origin_evidence
        observed = _external_resource_inventory('<script src="https://cdn.example.net/a.js"></script>', 'https://example.com/', 'example.com')
        resource = observed['external_resources'][0]
        self.assertIn('1 script(s)', _dependency_origin_evidence(observed, resource))
        self.assertIn('0 declared, 1 not declared', _dependency_origin_evidence(observed, resource))
        self.assertEqual(_dependency_origin_evidence({}, resource), 'Origin attributes not recorded')
        wrong = dict(resource, port=8443)
        self.assertEqual(_dependency_origin_evidence(observed, wrong), 'Origin attributes unavailable')
        block = observed['dependency_origin_observations']
        origin = copy.deepcopy(block['origins'][0])
        block['origins'].append(origin)
        self.assertEqual(_dependency_origin_evidence(observed, resource), 'Origin attributes unavailable')
        for count in (-1, True, '1', 1.5):
            block['origins'] = [dict(origin, script_reference_count=count)]
            self.assertEqual(_dependency_origin_evidence(observed, resource), 'Origin attributes unavailable')

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

class HTMLBaseInventoryTests(unittest.TestCase):
    def inventory(self, html):
        return _external_resource_inventory(html, 'https://example.com/page/index.html', 'example.com')

    def test_relative_dependencies_follow_first_base_even_when_it_is_later(self):
        result = self.inventory('<script src="app.js"></script><base href="https://cdn.example.net/assets/"><base href="https://ignored.example.net/"><link rel="stylesheet" href="style.css">')
        self.assertEqual(result['external_host_count'], 1)
        self.assertEqual(result['external_resources'][0]['host'], 'cdn.example.net')
        self.assertEqual(result['external_resources'][0]['reference_count'], 2)
        self.assertEqual(result['dependency_observations']['integrity_missing_reference_count'], 2)

    def test_empty_first_base_and_first_duplicate_attribute_are_preserved(self):
        self.assertEqual(self.inventory('<base href=""><base href="https://ignored.example.net/"><script src="a.js"></script>')['external_host_count'], 0)
        result = self.inventory('<base href="https://first.example.net/" href="https://second.example.net/"><script src="a.js" src="https://other.example.net/a.js"></script>')
        self.assertEqual(result['external_resources'][0]['host'], 'first.example.net')
        self.assertEqual(result['external_host_count'], 1)

    def test_absolute_links_keep_their_origin_and_relative_internal_bases_stay_internal(self):
        result = self.inventory('<base href="/assets/"><script src="app.js"></script><script src="//cdn.example.net/a.js"></script>')
        self.assertEqual(result['external_host_count'], 1)
        self.assertEqual(result['external_resources'][0]['host'], 'cdn.example.net')

    def test_invalid_and_disallowed_first_bases_use_document_fallback(self):
        for base in ['https://[bad', 'javascript:alert(1)', 'data:text/html,fixture']:
            with self.subTest(base=base):
                result = self.inventory('<base href="' + base + '"><base href="https://ignored.example.net/"><script src="a.js"></script><script src="https://cdn.example.net/a.js"></script>')
                self.assertEqual(result['external_host_count'], 1)
                self.assertEqual(result['external_resources'][0]['host'], 'cdn.example.net')
