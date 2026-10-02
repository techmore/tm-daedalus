import subprocess
import tempfile
from pathlib import Path
import unittest

from scripts.build_nmapui_source_bundle import _source_worktree_paths


class NmapUISourceProvenanceTests(unittest.TestCase):
    def test_manifest_can_identify_uncommitted_runtime_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"], check=True)
            (repository / "app.py").write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "app.py"], check=True)
            subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)

            (repository / "app.py").write_text("changed\n", encoding="utf-8")
            (repository / "new.py").write_text("untracked\n", encoding="utf-8")
            (repository / "notes.txt").write_text("not packaged\n", encoding="utf-8")

            paths = _source_worktree_paths(repository, {"app.py", "new.py"})
            self.assertEqual(paths, ["app.py", "new.py"])


if __name__ == "__main__":
    unittest.main()
