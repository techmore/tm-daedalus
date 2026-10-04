import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from scripts import install_nikto_runtime as runtime


class NiktoRuntimeTests(unittest.TestCase):
    def archive(self, unsafe=None):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as archive:
            info=tarfile.TarInfo('nikto-'+runtime.COMMIT+'/program/nikto.pl')
            info.size=7; archive.addfile(info,io.BytesIO(b'fixture'))
            if unsafe:
                info=tarfile.TarInfo('nikto-'+runtime.COMMIT+'/program/'+unsafe)
                info.type=tarfile.SYMTYPE; info.linkname='/etc/passwd';archive.addfile(info)
        return output.getvalue()

    def test_wrong_digest_does_not_create_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)/'runtime'
            with self.assertRaisesRegex(ValueError,'pinned source digest'):
                runtime.install(b'invalid archive',destination)
            self.assertFalse(destination.exists())

    def test_install_records_provenance_and_refuses_replacement(self):
        content=self.archive()
        with tempfile.TemporaryDirectory() as temporary,patch.object(runtime,'SHA256',hashlib.sha256(content).hexdigest()):
            destination=Path(temporary)/'runtime'
            result=runtime.install(content,destination)
            self.assertEqual(result['source_commit'],runtime.COMMIT)
            self.assertEqual((destination/'program/nikto.pl').read_bytes(),b'fixture')
            self.assertEqual((destination/'program/nikto.pl').stat().st_mode & 0o777,0o644)
            with self.assertRaisesRegex(ValueError,'already exists'):
                runtime.install(content,destination)

    def test_archive_links_are_refused_and_staging_is_removed(self):
        content=self.archive('unsafe-link')
        with tempfile.TemporaryDirectory() as temporary,patch.object(runtime,'SHA256',hashlib.sha256(content).hexdigest()):
            root=Path(temporary)
            with self.assertRaisesRegex(ValueError,'unexpected member'):
                runtime.install(content,root/'runtime')
            self.assertEqual(list(root.iterdir()),[])
