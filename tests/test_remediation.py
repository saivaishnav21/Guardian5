import json
import tempfile
import unittest
from pathlib import Path

from guardian.agents.base import RunContext
from guardian.agents.remediation import _build_proposal


class RemediationProposalTests(unittest.TestCase):
    def test_direct_npm_upgrade_is_bounded_and_has_no_fake_patch(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "target"
            target.mkdir()
            (target / "package.json").write_text(
                json.dumps({"dependencies": {"@demo/package": "1.0.0"}}), encoding="utf-8"
            )
            ctx = RunContext("https://github.com/example/app", Path(temp), state={
                "recon": {"target_dir": str(target), "manifests": ["package.json"],
                          "ecosystems": ["npm"], "commit": "a" * 40}
            })
            item = {"key": "example", "type": "vulnerability", "component": "@demo/package@1.0.0",
                    "fix": "2.0.0", "finding_ids": ["VULN-001"],
                    "ownership": {"direct": True, "dependency_path": []}}
            proposal = _build_proposal(ctx, item)
            self.assertEqual(proposal["result"], "upgrade")
            self.assertEqual(proposal["manifest_file"], "package.json")
            self.assertIn("--ignore-scripts", proposal["command"])
            self.assertIsNone(proposal["patch_sha256"])

            item["ownership"]["direct"] = False
            proposal = _build_proposal(ctx, item)
            self.assertEqual(proposal["result"], "manual_review")
            self.assertIsNone(proposal["command"])

            ctx.state["recon"]["ecosystems"] = ["pypi"]
            item["ownership"]["direct"] = True
            proposal = _build_proposal(ctx, item)
            self.assertEqual(proposal["result"], "manual_review")
            self.assertIsNone(proposal["command"])


if __name__ == "__main__":
    unittest.main()
