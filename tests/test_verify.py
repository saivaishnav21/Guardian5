import json
import tempfile
import unittest
from pathlib import Path

from guardian.verify import compare, write_comparison

COVERAGE = {"vulnerability": "completed", "container_ci": "completed",
            "container_image": "completed", "suspicious": "completed"}


def finding(fid, cve, component, severity="high"):
    return {"id": fid, "type": "vulnerability", "title": f"{cve} in {component}",
            "component": component, "severity": severity, "risk_level": severity,
            "evidence": {"cve_ids": [cve]}}


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _run(self, name, findings, coverage=None, ref="main", commit="a" * 40):
        run_dir = self.root / name
        run_dir.mkdir()
        (run_dir / "report.json").write_text(json.dumps({
            "guardian_report": {"repo_url": "https://github.com/o/r", "ref": ref,
                                "commit": commit},
            "scan_status": coverage or COVERAGE,
            "findings": findings,
        }), encoding="utf-8")
        return run_dir

    def test_resolved_finding_is_reported_and_keyed_independently_of_id(self):
        before = self._run("before", [finding("VULN-001", "CVE-2021-1", "a@1.0.0"),
                                      finding("VULN-002", "CVE-2021-2", "b@1.0.0")])
        # Same remaining finding, renumbered: ID changes must not read as resolved.
        after = self._run("after", [finding("VULN-001", "CVE-2021-2", "b@1.0.0")],
                          ref="fix", commit="b" * 40)
        result = compare(before, after, "VULN-001")
        self.assertEqual(result["verdict"], "improved")
        self.assertEqual(result["counts"]["resolved"], 1)
        self.assertEqual(result["counts"]["still_present"], 1)
        self.assertEqual(result["counts"]["newly_introduced"], 0)
        self.assertEqual(result["target_finding"]["status"], "resolved")

    def test_new_finding_makes_the_verdict_regressed(self):
        before = self._run("before", [finding("VULN-001", "CVE-2021-1", "a@1.0.0")])
        after = self._run("after", [finding("VULN-001", "CVE-2021-1", "a@1.0.0"),
                                    finding("VULN-002", "CVE-2022-9", "c@2.0.0")])
        result = compare(before, after)
        self.assertEqual(result["verdict"], "regressed")
        self.assertEqual(result["counts"]["newly_introduced"], 1)

    def test_missing_scanner_coverage_is_inconclusive_not_resolved(self):
        before = self._run("before", [finding("VULN-001", "CVE-2021-1", "a@1.0.0")])
        after = self._run("after", [], coverage={**COVERAGE,
                                                 "vulnerability": "not_run_missing_grype"})
        result = compare(before, after, "VULN-001")
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("vulnerability", result["incomparable_categories"])
        self.assertEqual(result["target_finding"]["status"], "inconclusive")

    def test_empty_rescan_with_full_coverage_is_clean(self):
        before = self._run("before", [finding("VULN-001", "CVE-2021-1", "a@1.0.0")])
        after = self._run("after", [])
        self.assertEqual(compare(before, after)["verdict"], "clean")

    def test_write_comparison_updates_the_candidate_report(self):
        before = self._run("before", [finding("VULN-001", "CVE-2021-1", "a@1.0.0")])
        after = self._run("after", [])
        result = compare(before, after, "VULN-001")
        path = write_comparison(result, after)
        self.assertTrue(path.is_file())
        report = json.loads((after / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["verification"]["verdict"], "clean")
        self.assertEqual(report["validation"]["status"], "not_run")

    def test_missing_report_is_rejected(self):
        before = self._run("before", [])
        with self.assertRaises(ValueError):
            compare(before, self.root / "does-not-exist")


if __name__ == "__main__":
    unittest.main()
