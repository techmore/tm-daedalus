import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'clients/csp-cis-audit/scripts/build-mdm-package.sh'

class CISMDMPackageTests(unittest.TestCase):
    def run_script(self, *arguments, env=None):
        return subprocess.run(['bash', str(SCRIPT), *map(str, arguments)], capture_output=True, text=True, env=env)

    def test_requires_app_and_fresh_output(self):
        self.assertEqual(self.run_script().returncode, 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(self.run_script(root / 'missing.app', root / 'out').returncode, 2)
            app = root / 'CSP-CIS_Audit.app'; app.mkdir()
            output = root / 'out'; output.mkdir()
            result = self.run_script(app, output)
            self.assertEqual(result.returncode, 2)
            self.assertIn('already exists', result.stderr)

    def fake_tools(self, root):
        directory = root / 'tools'; directory.mkdir()
        for name in ['codesign', 'security', 'xcrun', 'spctl', 'pkgbuild', 'productsign', 'pkgutil', 'ditto', 'shasum']:
            tool = directory / name
            tool.write_text('#!/bin/sh\nexit 0\n'); tool.chmod(0o755)
        return dict(os.environ, PATH=str(directory) + os.pathsep + os.environ['PATH'])

    def test_workspace_configuration_is_rejected_before_signing(self):
        for name in ['config.yaml', 'cis-client.yaml', 'CIS-CLIENT.YML']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); app = root / 'CSP-CIS_Audit.app'; app.mkdir()
                (app / name).write_text('fixture-secret-never-print')
                result = self.run_script(app, root / 'out', env=self.fake_tools(root))
                self.assertEqual(result.returncode, 2)
                self.assertIn('workspace configuration', result.stderr)
                self.assertNotIn('fixture-secret-never-print', result.stdout + result.stderr)
                self.assertFalse((root / 'out').exists())

    def test_untrusted_signature_is_rejected_without_creating_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); app = root / 'CSP-CIS_Audit.app'; app.mkdir()
            env = self.fake_tools(root)
            result = self.run_script(app, root / 'out', env=env)
            self.assertEqual(result.returncode, 2)
            self.assertIn('Developer ID Application', result.stderr)
            self.assertFalse((root / 'out').exists())

    def test_installer_identity_requires_matching_team(self):
        for identity in ['', 'Developer ID Installer: Fixture (ZZZZZZZZZZ)']:
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); app = root / 'CSP-CIS_Audit.app'; app.mkdir()
                env = self.fake_tools(root)
                (root / 'tools/codesign').write_text('#!/bin/sh\nif [ "$1" = "-dv" ]; then\n echo "Authority=Developer ID Application: Fixture (AAAAAAAAAA)" >&2\n echo "TeamIdentifier=AAAAAAAAAA" >&2\nfi\nexit 0\n')
                (root / 'tools/security').write_text('#!/bin/sh\ncat <<\'IDENTITY\'\n1) FIXTURE "' + identity + '"\nIDENTITY\n')
                result = self.run_script(app, root / 'out', env=env)
                self.assertEqual(result.returncode, 2)
                self.assertFalse((root / 'out').exists())
                self.assertIn('identity' if not identity else 'teams must match', result.stderr)

    def test_release_requires_notary_and_install_assessment(self):
        source = SCRIPT.read_text()
        self.assertIn('BundleIsRelocatable false', source)
        self.assertIn('Installer and application signing teams must match', source)
        self.assertIn('notarytool submit', source)
        self.assertIn('stapler validate "$csp_package"', source)
        self.assertIn('spctl --assess --type install', source)
        self.assertNotIn('--scripts', source)
        self.assertNotIn('launchctl', source)
        self.assertLess(source.index('spctl --assess --type install'), source.index('> SHA256SUMS'))
