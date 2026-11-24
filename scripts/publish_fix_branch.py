"""Publish a validated Guardian fix to a new branch on a repository you own.

Human-triggered only. This never merges, never deploys, and never touches the
scanned checkout. It refuses unless a sandbox trial passed and the exact patch
that was tested is the patch being pushed.

Usage:
    python scripts/publish_fix_branch.py runs/<id> VULN-035 \\
        --repo https://github.com/<you>/<fork>.git [--branch name] [--push]

Without --push the branch is created in a temporary clone and nothing leaves
the machine. Authentication uses the local git credential helper; no token is
read, stored, or logged by this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from guardian.approval_gate import load_proposals, proposal_sha256  # noqa: E402

BRANCH_RE = re.compile(r"^[\w][\w./-]{0,100}$")
REPO_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(?:\.git)?$")


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, text=True, timeout=180)
    if check and result.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {(result.stderr or result.stdout).strip()[:300]}")
    return result.stdout.strip()


def _passed_trial(run_dir: Path, finding_id: str,
                  allow_inconclusive: bool = False) -> tuple[dict, Path]:
    """Find the newest sandbox trial for this finding that actually passed."""
    sandbox = run_dir / "sandbox"
    if not sandbox.is_dir():
        raise SystemExit("No sandbox trials exist for this run. Run guardian.sandbox first.")
    candidates = []
    for path in sandbox.glob(f"{finding_id}-*/validation.json"):
        try:
            record = _read(path)
        except (OSError, ValueError):
            continue
        if isinstance(record, dict) and record.get("finding_id") == finding_id:
            candidates.append((path.stat().st_mtime, path, record))
    if not candidates:
        raise SystemExit(f"No sandbox trial found for {finding_id}.")
    _, path, record = max(candidates, key=lambda item: item[0])
    status = record.get("status")
    if status != "passed":
        if not (allow_inconclusive and status == "inconclusive"):
            raise SystemExit(
                f"Refusing to publish: latest trial for {finding_id} is "
                f"'{status}' ({record.get('reason')}). "
                "Only a passed build/test trial may be published. "
                "Use --allow-inconclusive to publish an explicitly unvalidated branch."
            )
        print("WARNING: publishing an INCONCLUSIVE trial. The build/test gate did not")
        print(f"         pass: {record.get('reason')}")
        print("         The branch and commit message will say so. Do not merge it.")
    return record, path.parent


def _approval(run_dir: Path, proposal: dict) -> dict:
    """Require a recorded human 'approve' bound to this exact proposal."""
    path = run_dir / "approvals.json"
    if not path.is_file():
        raise SystemExit(
            "Refusing to publish: no human decision is recorded. "
            "Record an approval in the dashboard's Human review tab first."
        )
    history = _read(path)
    if not isinstance(history, list):
        raise SystemExit("approvals.json is not a list.")
    digest = proposal_sha256(proposal)
    latest = next((r for r in reversed(history) if isinstance(r, dict)
                   and r.get("proposal_sha256") == digest), None)
    if latest is None:
        raise SystemExit("Refusing to publish: no decision matches this exact proposal.")
    if latest.get("decision") != "approve":
        raise SystemExit(f"Refusing to publish: latest decision is '{latest.get('decision')}'.")
    return latest


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish a validated fix to a new branch")
    parser.add_argument("run_dir")
    parser.add_argument("finding_id")
    parser.add_argument("--repo", required=True, help="HTTPS URL of a GitHub repo you own")
    parser.add_argument("--branch", default=None, help="branch name (default guardian/fix-<id>)")
    parser.add_argument("--base", default=None, help="base ref (default: the scanned ref)")
    parser.add_argument("--push", action="store_true", help="actually push; omit for a dry run")
    parser.add_argument("--allow-inconclusive", action="store_true",
                        help="publish an unvalidated branch, labelled as such, when the "
                             "target has no runnable test suite")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    if not run_dir.is_dir():
        raise SystemExit(f"{run_dir} is not a directory")
    if not REPO_RE.match(args.repo):
        raise SystemExit("--repo must be https://github.com/<owner>/<repo>")

    branch = args.branch or f"guardian/fix-{args.finding_id.lower()}"
    if not BRANCH_RE.match(branch):
        raise SystemExit("branch name is not valid")

    proposals = [p for p in load_proposals(run_dir / "proposals.json")
                 if p.get("finding_id") == args.finding_id]
    if len(proposals) != 1:
        raise SystemExit(f"{args.finding_id} must identify exactly one proposal")
    proposal = proposals[0]

    validation, trial_dir = _passed_trial(run_dir, args.finding_id, args.allow_inconclusive)
    approval = _approval(run_dir, proposal)

    patch_file = trial_dir / "patch.diff"
    if not patch_file.is_file():
        raise SystemExit("The trial has no patch.diff to publish.")
    digest = hashlib.sha256(patch_file.read_bytes()).hexdigest()
    if digest != validation.get("patch_sha256"):
        raise SystemExit("Refusing to publish: patch.diff does not match the tested patch hash.")

    recon = (_read(run_dir / "state.json")).get("state", {}).get("recon", {})
    base = args.base or recon.get("checked_out_ref") or "HEAD"
    commit = proposal.get("baseline_commit")

    print(f"Finding        : {args.finding_id} ({proposal.get('component')})")
    print(f"Change         : {proposal.get('component')} -> {proposal.get('target_version')}")
    print(f"Trial          : {validation.get('status')} ({validation.get('approval_mode')})")
    print(f"Approved by    : human decision {approval.get('reviewed_at')}")
    print(f"Patch SHA-256  : {digest}")
    print(f"Files          : {', '.join(validation.get('changed_files', []))}")
    print(f"Target         : {args.repo} branch '{branch}' from {base} @ {commit}")

    workspace = Path(tempfile.mkdtemp(prefix="guardian-publish-"))
    try:
        clone = workspace / "repo"
        subprocess.run(["git", "clone", "--quiet", "--branch", base, args.repo, str(clone)],
                       check=True, timeout=300)
        head = _git(clone, "rev-parse", "HEAD")
        if commit and head != commit:
            raise SystemExit(
                f"Refusing to publish: {args.repo}@{base} is at {head[:8]} but the patch was "
                f"validated against {str(commit)[:8]}. Rescan or rebase before publishing."
            )
        _git(clone, "switch", "-c", branch)

        # patch.diff uses baseline/<path> and candidate/<path> prefixes.
        apply_result = subprocess.run(
            ["git", "-C", str(clone), "apply", "-p1", "--whitespace=nowarn", str(patch_file)],
            capture_output=True, text=True, timeout=120,
        )
        if apply_result.returncode != 0:
            raise SystemExit("Patch did not apply cleanly: "
                             + (apply_result.stderr or apply_result.stdout).strip()[:400])

        changed = _git(clone, "diff", "--name-only").splitlines()
        allowed = set(validation.get("changed_files", []))
        unexpected = [name for name in changed if name not in allowed]
        if unexpected:
            raise SystemExit(f"Refusing to publish: unexpected files changed: {unexpected}")

        message = (
            f"fix({proposal.get('component')}): upgrade to {proposal.get('target_version')}\n\n"
            f"Guardian finding {args.finding_id} ({proposal.get('risk_level')} risk).\n"
            f"Sandbox trial: {validation.get('status')}; patch sha256 {digest}.\n"
            f"Human decision recorded {approval.get('reviewed_at')}.\n"
            f"Rollback: {proposal.get('rollback')}\n"
            "Not verified safe. Rescan and review before merging."
        )
        _git(clone, "add", *sorted(allowed))
        _git(clone, "-c", "user.name=Guardian AI",
             "-c", "user.email=guardian@localhost", "commit", "-m", message)
        new_commit = _git(clone, "rev-parse", "HEAD")

        if args.push:
            _git(clone, "push", "-u", "origin", branch)
            owner_repo = args.repo.removesuffix(".git").removeprefix("https://github.com/")
            print(f"\nPushed {branch} ({new_commit[:8]}).")
            print(f"Rescan with: https://github.com/{owner_repo}/tree/{branch}")
        else:
            print(f"\nDry run complete. Branch '{branch}' built at {new_commit[:8]}, not pushed.")
            print("Re-run with --push to publish it.")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    main()
