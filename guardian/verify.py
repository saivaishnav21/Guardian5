"""Before/after rescan comparison (Day 2, step 5).

Compares two completed Guardian runs by a stable finding key, so a fix branch
can be rescanned and judged against its baseline. Finding IDs (VULN-001...) are
positional and renumber between scans, so they are never used for matching.

Usage:
    python -m guardian.verify <baseline_run_dir> <candidate_run_dir> [--finding-id VULN-035]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from guardian.risk import group_key, normalize_severity

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


def _read(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_report(run_dir: Path) -> dict:
    report = run_dir / "report.json"
    if not report.is_file():
        raise ValueError(f"{run_dir.name} has no report.json; run a full scan first")
    data = _read(report)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"{report} is not a Guardian report")
    return data


def _index(findings: list) -> dict[str, dict]:
    """Map stable key -> representative finding. Keeps the worst severity seen."""
    index: dict[str, dict] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = group_key(finding)
        current = index.get(key)
        if current is None:
            index[key] = finding
            continue
        rank = SEVERITY_ORDER.index(normalize_severity(finding.get("severity")))
        if rank < SEVERITY_ORDER.index(normalize_severity(current.get("severity"))):
            index[key] = finding
    return index


def _describe(key: str, finding: dict) -> dict:
    return {
        "key": key,
        "id_in_run": finding.get("id"),
        "type": finding.get("type"),
        "title": finding.get("title"),
        "component": finding.get("component"),
        "severity": normalize_severity(finding.get("severity")),
        "risk_level": finding.get("risk_level", "unrated"),
    }


def _counts(items: list[dict]) -> dict:
    counts = {level: 0 for level in SEVERITY_ORDER}
    for item in items:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return {level: count for level, count in counts.items() if count}


def _coverage(report: dict) -> dict:
    status = report.get("scan_status") or {}
    return {key: status.get(key, "not_run") for key in
            ("vulnerability", "container_ci", "container_image", "suspicious")}


def _comparable(before: dict, after: dict) -> tuple[list[str], list[str]]:
    """A category scanned in one run but not the other cannot be compared."""
    incomparable, notes = [], []
    before_cov, after_cov = _coverage(before), _coverage(after)
    for category, before_status in before_cov.items():
        after_status = after_cov[category]
        if before_status != after_status:
            incomparable.append(category)
            notes.append(f"{category}: baseline={before_status}, candidate={after_status}")
    return incomparable, notes


def compare(baseline_run: str | Path, candidate_run: str | Path,
            finding_id: str | None = None) -> dict:
    """Diff two scan runs. Never reports an unscanned category as resolved."""
    baseline_dir, candidate_dir = Path(baseline_run), Path(candidate_run)
    before, after = _load_report(baseline_dir), _load_report(candidate_dir)

    before_index, after_index = _index(before["findings"]), _index(after["findings"])
    before_keys, after_keys = set(before_index), set(after_index)

    resolved = [_describe(k, before_index[k]) for k in sorted(before_keys - after_keys)]
    still_present = [_describe(k, after_index[k]) for k in sorted(before_keys & after_keys)]
    newly_introduced = [_describe(k, after_index[k]) for k in sorted(after_keys - before_keys)]

    incomparable, notes = _comparable(before, after)

    target = None
    if finding_id:
        match = next((k for k, f in before_index.items() if f.get("id") == finding_id), None)
        if match is None:
            target = {"finding_id": finding_id, "status": "not_found_in_baseline"}
        else:
            target = {
                "finding_id": finding_id,
                "key": match,
                "component": before_index[match].get("component"),
                "status": "resolved" if match not in after_keys else "still_present",
            }
            if incomparable and before_index[match].get("type") in incomparable:
                target["status"] = "inconclusive"

    before_header = before.get("guardian_report") or {}
    after_header = after.get("guardian_report") or {}

    if incomparable:
        verdict = "inconclusive"
        summary = "Scanner coverage differs between the two runs; some categories cannot be compared."
    elif newly_introduced:
        verdict = "regressed"
        summary = f"{len(newly_introduced)} finding(s) appear only in the candidate scan."
    elif target and target["status"] == "still_present":
        verdict = "not_resolved"
        summary = "The target finding is still present after the change."
    elif not after_keys:
        verdict = "clean"
        summary = "No findings remain in the candidate scan."
    elif resolved:
        verdict = "improved"
        summary = (f"{len(resolved)} finding(s) resolved, {len(still_present)} remain, "
                   "0 newly introduced.")
    else:
        verdict = "unchanged"
        summary = "No findings were resolved and none were introduced."

    return {
        "schema_version": 1,
        "verdict": verdict,
        "summary": summary,
        "baseline": {
            "run_dir": str(baseline_dir), "repo_url": before_header.get("repo_url"),
            "ref": before_header.get("ref"), "commit": before_header.get("commit"),
            "total_findings": len(before["findings"]), "unique_keys": len(before_keys),
            "coverage": _coverage(before),
        },
        "candidate": {
            "run_dir": str(candidate_dir), "repo_url": after_header.get("repo_url"),
            "ref": after_header.get("ref"), "commit": after_header.get("commit"),
            "total_findings": len(after["findings"]), "unique_keys": len(after_keys),
            "coverage": _coverage(after),
        },
        "target_finding": target,
        "counts": {
            "resolved": len(resolved), "still_present": len(still_present),
            "newly_introduced": len(newly_introduced),
            "resolved_by_severity": _counts(resolved),
            "newly_introduced_by_severity": _counts(newly_introduced),
        },
        "resolved": resolved,
        "newly_introduced": newly_introduced,
        "still_present": still_present,
        "incomparable_categories": incomparable,
        "coverage_notes": notes,
        "limitations": [
            "Matching uses type + advisory ID + component; a renamed component reads as resolved plus newly introduced.",
            "A resolved finding means the scanner no longer reports it, not that the code is proven safe.",
            "Scanner database versions are not pinned between runs.",
        ],
    }


def latest_validation(run_dir: str | Path) -> dict | None:
    """Most recent sandbox build/test record for a run, if one exists."""
    sandbox = Path(run_dir) / "sandbox"
    files = sorted(sandbox.glob("*/validation.json"), key=lambda p: p.stat().st_mtime,
                   reverse=True) if sandbox.is_dir() else []
    for path in files:
        try:
            record = _read(path)
        except (OSError, ValueError):
            continue
        if isinstance(record, dict):
            record["artifact"] = str(path)
            return record
    return None


def write_comparison(result: dict, candidate_run: str | Path) -> Path:
    """Save the comparison and fold it into the candidate run's report.json."""
    run_dir = Path(candidate_run)
    path = run_dir / "comparison.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    report_path = run_dir / "report.json"
    if report_path.is_file():
        try:
            report = _read(report_path)
        except (OSError, ValueError):
            return path
        if isinstance(report, dict):
            validation = latest_validation(run_dir)
            report["validation"] = ({
                "status": validation.get("status"), "reason": validation.get("reason"),
                "finding_id": validation.get("finding_id"),
                "approval_mode": validation.get("approval_mode"),
                "patch_sha256": validation.get("patch_sha256"),
                "artifact": validation.get("artifact"),
            } if validation else {"status": "not_run", "reason": "no sandbox trial for this run"})
            report["verification"] = {
                "verdict": result["verdict"], "summary": result["summary"],
                "counts": result["counts"], "target_finding": result["target_finding"],
                "artifact": str(path),
            }
            report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare a baseline scan with a rescan")
    parser.add_argument("baseline_run", help="run directory scanned before the fix")
    parser.add_argument("candidate_run", help="run directory scanned after the fix")
    parser.add_argument("--finding-id", default=None, help="baseline finding the fix targeted")
    args = parser.parse_args()

    result = compare(args.baseline_run, args.candidate_run, args.finding_id)
    path = write_comparison(result, args.candidate_run)
    print(json.dumps({
        "verdict": result["verdict"], "summary": result["summary"],
        "counts": result["counts"], "target_finding": result["target_finding"],
        "incomparable_categories": result["incomparable_categories"],
        "artifact": str(path),
    }, indent=2))


if __name__ == "__main__":
    main()
