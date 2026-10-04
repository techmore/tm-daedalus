from pathlib import Path
import tempfile
import unittest
from daedalus.report_storage import report_artifact

class ReportStorageTests(unittest.TestCase):
    def test_workspace_file_is_portable_and_missing_files_remain_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / '1').mkdir()
            pdf = root / '1' / 'saved.pdf'; pdf.write_bytes(b'%PDF-fixture')
            self.assertEqual(report_artifact(root, 1, 'saved.pdf'), pdf.resolve())
            with self.assertRaises(FileNotFoundError):
                report_artifact(root, 2, 'saved.pdf')
            with self.assertRaises(FileNotFoundError):
                report_artifact(root, 1, 'missing.pdf')

    def test_traversal_and_unsupported_names_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ['../2/saved.pdf', '/tmp/saved.pdf', 'sub/file.pdf', 'sub\\file.pdf', '.', '', 'file.json', 'bad\x00.pdf']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    report_artifact(Path(tmp), 1, name)

    def test_artifact_and_workspace_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / '1').mkdir(); (root / '2').mkdir()
            other = root / '2/saved.pdf'; other.write_bytes(b'%PDF-fixture')
            (root / '1/saved.pdf').symlink_to(other)
            with self.assertRaises(ValueError):
                report_artifact(root, 1, 'saved.pdf')
            (root / '3').symlink_to(root / '2')
            with self.assertRaises(ValueError):
                report_artifact(root, 3, 'saved.pdf')
