"""Record a human review decision for one proposal from the command line.

This is the same decision the dashboard's Human review tab records. Running it
is the human act; the script does not decide anything on its own.

Usage:
    python scripts/record_approval.py runs/<id> VULN-035 --decision approve \\
        --reason "Reviewed diff and dependency path; approved for sandbox trial."
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from guardian.approval_gate import (  # noqa: E402
    create_preflight_review, load_proposals, save_preflight_review,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Record a human decision for one proposal")
    parser.add_argument("run_dir")
    parser.add_argument("finding_id")
    parser.add_argument("--decision", required=True,
                        choices=["approve", "reject", "request_changes"])
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    report_path = run_dir / "report.json"
    if not report_path.is_file():
        raise SystemExit(f"{report_path} is missing; run a full scan first")
    report = json.loads(report_path.read_text(encoding="utf-8"))

    proposals = [p for p in load_proposals(run_dir / "proposals.json")
                 if p.get("finding_id") == args.finding_id]
    if len(proposals) != 1:
        raise SystemExit(f"{args.finding_id} must identify exactly one proposal")
    proposal = proposals[0]

    review = create_preflight_review(
        proposal=proposal, report=report, source_file=run_dir / "proposals.json",
        decision=args.decision, reason=args.reason,
    )
    saved = save_preflight_review(review, run_dir)
    print(f"Recorded '{args.decision}' for {args.finding_id} ({proposal.get('component')})")
    print(f"  proposal_sha256 : {review['proposal_sha256']}")
    print(f"  reviewed_at     : {review['reviewed_at']}")
    print(f"  identity        : unverified local reviewer (no identity system in this demo)")
    print(f"  saved           : {saved}")
    print("  scope           : sandbox trial only; adoption still requires a separate decision")


if __name__ == "__main__":
    main()
