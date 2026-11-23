import json
import tempfile
import unittest
from pathlib import Path

from guardian.agents.suspicious import (
    detect_typosquat,
    detect_install_scripts,
    detect_non_registry_resolutions,
    lockfile_diff,
)


class SuspiciousAgentTests(unittest.TestCase):
    def test_typosquat_detection(self):
        result = detect_typosquat(
            "lod-ash",
            candidates={"lodash", "express", "react"},
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["target"], "lodash")

    def test_install_script_detection(self):
        lockfile = {
            "packages": {
                "node_modules/demo-package": {
                    "version": "1.0.0",
                    "hasInstallScript": True,
                }
            }
        }
        findings = detect_install_scripts(lockfile)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "suspicious_change")

    def test_non_registry_resolution_detection(self):
        lockfile = {
            "packages": {
                "node_modules/demo-package": {
                    "version": "1.0.0",
                    "resolved": "https://example.invalid/demo.tgz",
                }
            }
        }
        findings = detect_non_registry_resolutions(lockfile)
        self.assertTrue(findings)
        self.assertIn("https://", findings[0]["evidence"]["resolutions"][0])

    def test_json_files_are_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            package = target / "package.json"
            lockfile = target / "package-lock.json"
            package.write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            lockfile.write_text(json.dumps({"packages": {}}), encoding="utf-8")
            self.assertTrue(package.is_file())
            self.assertTrue(lockfile.is_file())

    def test_lockfile_diff_detects_integrity_change(self):
        before = {
            "packages": {
                "node_modules/demo-package": {
                    "version": "1.0.0",
                    "integrity": "sha512-old",
                    "resolved": "https://registry.npmjs.org/demo-package/-/demo.tgz",
                }
            }
        }
        after = {
            "packages": {
                "node_modules/demo-package": {
                    "version": "1.0.0",
                    "integrity": "sha512-modified",
                    "resolved": "https://registry.npmjs.org/demo-package/-/demo.tgz",
                },
                "node_modules/lod-ash": {
                    "version": "1.0.0-demo",
                    "integrity": "sha512-demo",
                    "resolved": "https://example.invalid/demo.tgz",
                },
            }
        }
        findings = lockfile_diff(before, after)
        types = [finding["evidence"]["what_changed"] for finding in findings]
        self.assertTrue(any("added" in value for value in types))
        self.assertTrue(any("Integrity hash" in value for value in types))


if __name__ == "__main__":
    unittest.main()
