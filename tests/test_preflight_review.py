import json
import tempfile
import unittest
from pathlib import Path

from guardian.approval_gate import (
    create_preflight_review, may_auto_trial, may_trial, proposal_sha256, trial_route,
)


class PreflightReviewTests(unittest.TestCase):
    def test_threshold_routes_only_supported_candidates_and_honors_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "proposals.json"
            proposal = {
                "finding_id": "VULN-001", "component": "demo@1.0.0", "result": "upgrade",
                "repo_url": "https://github.com/example/demo", "baseline_commit": "a" * 40,
                "confidence_score": 70, "manifest_file": "package.json",
                "target_version": "1.0.1", "command": "npm install --ignore-scripts demo@1.0.1",
            }
            report = {
                "guardian_report": {"repo_url": proposal["repo_url"], "commit": "a" * 40},
                "findings": [{"id": "VULN-001", "component": "demo@1.0.0"}],
            }
            source.write_text(json.dumps([proposal]), encoding="utf-8")
            self.assertEqual(trial_route(proposal)["route"], "auto_sandbox_trial")
            self.assertEqual(may_auto_trial(proposal, report, source), [])
            self.assertEqual(trial_route({**proposal, "confidence_score": 69})["route"], "manual_review")
            self.assertEqual(trial_route({**proposal, "result": "manual_review"})["route"], "manual_review")
            (Path(temp) / "approvals.json").write_text(json.dumps([
                {"proposal_sha256": proposal_sha256(proposal), "decision": "reject"}
            ]), encoding="utf-8")
            self.assertIn("a human rejected the proposal or requested changes",
                          may_auto_trial(proposal, report, source))

    def test_review_binds_current_proposal_and_baseline_without_a_name(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "proposals.json"
            proposal = {
                "finding_id": "VULN-001", "component": "demo@1.0.0", "result": "upgrade",
                "repo_url": "https://github.com/example/demo", "baseline_commit": "a" * 40,
            }
            source.write_text(json.dumps([proposal]), encoding="utf-8")
            report = {
                "guardian_report": {"repo_url": proposal["repo_url"], "commit": "a" * 40},
                "findings": [{"id": "VULN-001", "component": "demo@1.0.0"}],
            }
            review = create_preflight_review(
                proposal=proposal, report=report, source_file=source,
                decision="approve", reason="Reviewed the bounded sandbox candidate",
            )
            self.assertEqual(review["reviewer"]["method"], "local_ui")
            self.assertFalse(review["reviewer"]["identity_verified"])
            self.assertEqual(may_trial(review, proposal, report, source), [])

            changed = {**proposal, "component": "other@1.0.0"}
            self.assertIn("proposal changed after review", may_trial(review, changed, report, source))


if __name__ == "__main__":
    unittest.main()
