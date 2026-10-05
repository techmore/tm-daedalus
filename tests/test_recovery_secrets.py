import json
import tempfile
import unittest
from pathlib import Path
from scripts.recovery_secrets import seal, unseal, read_private, write_new_private


class RecoverySecretsTests(unittest.TestCase):
    def test_roundtrip_is_randomized_and_contains_no_clear_secret(self):
        clear = b'DAEDALUS_ENCRYPTION_KEY=synthetic-private-value\n'
        first = seal(clear, 'synthetic-password-123')
        self.assertNotEqual(first, seal(clear, 'synthetic-password-123'))
        self.assertNotIn(b'synthetic-private-value', first)
        self.assertEqual(unseal(first, 'synthetic-password-123'), clear)

    def test_wrong_password_tampering_and_unbounded_parameters_are_rejected(self):
        envelope = seal(b'synthetic-secret', 'synthetic-password-123')
        with self.assertRaises(ValueError):
            unseal(envelope, 'different-password-123')
        value = json.loads(envelope)
        value['token'] = value['token'][:-4] + 'AAAA'
        with self.assertRaises(ValueError):
            unseal(json.dumps(value).encode(), 'synthetic-password-123')
        value['n'] = 2 ** 30
        with self.assertRaises(ValueError):
            unseal(json.dumps(value).encode(), 'synthetic-password-123')

    def test_private_files_and_existing_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private'
            write_new_private(path, b'fixture')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(read_private(path, 100), b'fixture')
            with self.assertRaises(FileExistsError):
                write_new_private(path, b'replacement')
            self.assertEqual(path.read_bytes(), b'fixture')
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                read_private(link, 100)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_private(path, 100)

    def test_empty_large_and_short_password_inputs_are_refused(self):
        for contents, password in [(b'', 'synthetic-password-123'), (b'x' * (1024 * 1024 + 1), 'synthetic-password-123'), (b'x', 'short')]:
            with self.subTest(size=len(contents)), self.assertRaises(ValueError):
                seal(contents, password)
