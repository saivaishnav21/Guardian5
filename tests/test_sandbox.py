import tempfile
import unittest
from pathlib import Path

from guardian.sandbox import _diff_allowed, _test_log_caveat, _test_reliability_note


class SandboxChecksTests(unittest.TestCase):
    def test_diff_rejects_unlisted_file_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline, candidate = root / "baseline", root / "candidate"
            baseline.mkdir()
            candidate.mkdir()
            for folder, version in ((baseline, "1.0.0"), (candidate, "1.0.1")):
                (folder / "package.json").write_text(version, encoding="utf-8")
            changed, patch = _diff_allowed(baseline, candidate, {"package.json"})
            self.assertEqual(changed, ["package.json"])
            self.assertIn(b"1.0.1", patch)
            (candidate / "unexpected.txt").write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError):
                _diff_allowed(baseline, candidate, {"package.json"})

    def test_empty_or_forced_test_results_are_inconclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Gruntfile.js").write_text('grunt.option("force", true);', encoding="utf-8")
            log = root / "test.log"
            log.write_text("No files to check...OK\nDone.\n", encoding="utf-8")
            self.assertIsNotNone(_test_reliability_note(root))
            self.assertIsNotNone(_test_log_caveat(str(log)))


if __name__ == "__main__":
    unittest.main()
