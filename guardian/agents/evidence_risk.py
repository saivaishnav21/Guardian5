"""
Evidence & Risk Agent  –  guardian/agents/evidence_risk.py
==========================================================
Person 5 contribution.

Responsibilities
----------------
1. Read raw findings produced by earlier agents from ctx.state["findings"].
2. Validate every finding: required fields, ID format, evidence dict non-empty.
3. Assign a transparent severity-based risk_level.
4. Enrich findings with concise remediation recommendations.
5. Optionally request structured AI review priority and suspicious hypotheses.
6. Save processed output via ctx.save().

Design rules (hallucination prevention)
----------------------------------------
- Scanner risk levels remain deterministic; AI may suggest review order only.
- AI output is checked against known IDs, versions, and evidence references.
- If the API key is absent or the call fails, the deterministic fallback is used.
"""

from __future__ import annotations

import re
from typing import Any

from guardian.agents.base import RunContext
from guardian.ai_review import review as ai_review
from guardian.secrets import groq_key

AGENT = "Evidence & Risk Agent"

# ---------------------------------------------------------------------------
# ID patterns that each source agent should produce
# ---------------------------------------------------------------------------
_VALID_ID_RE = re.compile(
    r"^(VULN|SUSP|CTR|CI|FINDING|PKG|DEP)-\d{3,}$", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Severity → base risk mapping  (deterministic, no AI)
# ---------------------------------------------------------------------------
_SEVERITY_BASE: dict[str, str] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "unknown":  "unrated",
}

# Evidence quality modifiers
_QUALITY_BOOST = {"nvd", "osv", "github_advisory", "snyk", "grype", "trivy", "static inspection"}
_QUALITY_LABEL = {True: "named scanner or static check", False: "unidentified source"}
_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unrated": 4}
MAX_AI_RISK_REVIEWS = 6


# ---------------------------------------------------------------------------
# Deterministic risk assignment
# ---------------------------------------------------------------------------

def _evidence_quality(evidence: dict) -> bool:
    """Return True if evidence names a recognised scanner or static check."""
    if not evidence:
        return False
    source = str(evidence.get("source", "")).lower()
    tool   = str(evidence.get("tool",   "")).lower()
    # Accept if any recognised word appears anywhere in source/tool
    return any(q in source or q in tool for q in _QUALITY_BOOST)


def _assign_risk(severity: str, evidence: dict) -> tuple[str, str]:
    """Return an initial risk level from severity, with evidence-source context."""
    sev   = severity.lower() if severity else "unknown"
    base  = _SEVERITY_BASE.get(sev, "unrated")
    confirmed = _evidence_quality(evidence)
    quality   = _QUALITY_LABEL[confirmed]

    rationale = (
        f"Initial risk follows reported severity '{sev}'. Evidence source: {quality}; "
        "exploitability, reachability, exposure and provenance have not been established."
    )
    return base, rationale


# ---------------------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = ["id", "type", "title", "component", "severity"]


def _validate_finding(raw: dict) -> list[str]:
    """Return a list of validation errors (empty list = OK)."""
    errors: list[str] = []

    for field in _REQUIRED_FIELDS:
        if not raw.get(field):
            errors.append(f"Missing required field: '{field}'")

    fid = raw.get("id", "")
    if fid and not _VALID_ID_RE.match(str(fid)):
        errors.append(
            f"Finding ID '{fid}' does not match expected pattern "
            f"(e.g. VULN-001, SUSP-001, CTR-001, CI-001)."
        )

    evidence = raw.get("evidence")
    if evidence is not None and not isinstance(evidence, dict):
        errors.append(f"'evidence' must be a dict, got {type(evidence).__name__}.")
    elif not evidence:
        errors.append("Finding has no supporting evidence.")

    return errors


# ---------------------------------------------------------------------------
# Remediation library  (deterministic, offline)
# ---------------------------------------------------------------------------

_REMEDIATION_BY_TYPE: dict[str, str] = {
    "vulnerability": (
        "Pin or upgrade the affected package to a patched version. "
        "Verify the fix in a staging environment and re-run the scanner."
    ),
    "suspicious_change": (
        "Review the commit that introduced this change. "
        "If unauthorised, revert and rotate any secrets that may have been exposed."
    ),
    "container": (
        "Update the affected image package or base image, then rebuild and rescan. "
        "Review the image configuration separately."
    ),
    "ci_cd": (
        "Audit the CI/CD workflow for use of unversioned action references. "
        "Pin all third-party actions to a specific commit SHA."
    ),
}

_DEFAULT_REMEDIATION = (
    "Review the finding manually. Consult the evidence field for supporting data "
    "and apply the principle of least privilege."
)


def _get_remediation(finding_type: str, fix_hint: str | None) -> str:
    base = _REMEDIATION_BY_TYPE.get(finding_type.lower(), _DEFAULT_REMEDIATION)
    if fix_hint:
        return f"{base} Suggested fix from scanner: {fix_hint}"
    return base


# ---------------------------------------------------------------------------
# Main agent entry point
# ---------------------------------------------------------------------------

def run(ctx: RunContext) -> None:  # noqa: C901
    raw_findings: list[dict] = ctx.state.get("findings", [])

    if not isinstance(raw_findings, list):
        ctx.note(AGENT, "ctx.state['findings'] is not a list – skipping.")
        ctx.save("evidence_risk.json", {"processed": [], "skipped": [], "summary": {}})
        return

    if not raw_findings:
        ctx.state["processed_findings"] = []
        ctx.state["skipped_findings"] = []
        ctx.note(AGENT, "No findings to process.")
        ctx.save("evidence_risk.json", {
            "processed": [],
            "skipped": [],
            "summary": {
                "total_input": 0,
                "total_valid": 0,
                "total_skipped": 0,
                "risk_counts": {},
                "ai_available": bool(groq_key()),
            },
        })
        return

    ctx.note(AGENT, f"Processing {len(raw_findings)} finding(s).")

    processed: list[dict] = []
    skipped:   list[dict] = []

    # Count by risk level for summary
    risk_counts: dict[str, int] = {}

    for idx, raw in enumerate(raw_findings):
        if not isinstance(raw, dict):
            skipped.append({"index": idx, "reason": "Finding is not a dict.", "raw": str(raw)})
            continue

        errors = _validate_finding(raw)
        if errors:
            skipped.append({"index": idx, "id": raw.get("id"), "errors": errors, "raw": raw})
            ctx.note(AGENT, f"  Skipped finding[{idx}] id={raw.get('id')!r}: {errors}")
            continue

        # -----------------------------------------------------------------
        # Deep-copy to avoid mutating original state
        # -----------------------------------------------------------------
        f: dict[str, Any] = dict(raw)

        # Preserve original fields
        original_severity  = f.get("severity", "unknown")
        original_risk      = f.get("risk_level", "unrated")
        original_evidence  = f.get("evidence") or {}
        dependency_path    = f.get("dependency_path", [])

        # -----------------------------------------------------------------
        # Deterministic risk assignment
        # -----------------------------------------------------------------
        risk_level, risk_rationale = _assign_risk(original_severity, original_evidence)
        f["risk_level"]    = risk_level
        f["risk_rationale"] = risk_rationale

        # -----------------------------------------------------------------
        # Remediation recommendation
        # -----------------------------------------------------------------
        remediation = _get_remediation(f.get("type", ""), f.get("fix"))
        f["remediation"] = remediation

        # -----------------------------------------------------------------
        # Dependency path  (preserve if already set, else keep empty list)
        # -----------------------------------------------------------------
        if not dependency_path:
            f["dependency_path"] = []

        # -----------------------------------------------------------------
        # Advisory review order is kept separate from scanner risk.
        # -----------------------------------------------------------------
        f["review_priority"] = risk_level
        suspicious_review = ctx.state.get("ai_suspicious", {}).get(f["id"])
        if suspicious_review:
            f["ai_suspicious"] = suspicious_review

        # -----------------------------------------------------------------
        # Tracking metadata
        # -----------------------------------------------------------------
        f["_original_risk_level"] = original_risk
        f["_processed_by"]        = AGENT

        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        processed.append(f)
        ctx.note(AGENT, f"  [{f['id']}] {f['title'][:60]} -> risk={risk_level}")

    ordered = sorted(processed, key=lambda item: (
        _RISK_ORDER.get(item["risk_level"], 99), item["id"]
    ))
    selected: list[dict] = []
    selected_ids: set[str] = set()
    seen_types: set[str] = set()
    for finding in ordered:
        if finding["type"] not in seen_types and len(selected) < MAX_AI_RISK_REVIEWS:
            selected.append(finding)
            selected_ids.add(finding["id"])
            seen_types.add(finding["type"])
    for finding in ordered:
        if len(selected) >= MAX_AI_RISK_REVIEWS:
            break
        if finding["id"] not in selected_ids:
            selected.append(finding)
            selected_ids.add(finding["id"])

    risk_reviews = {}
    for finding in selected:
        assessment = ai_review("risk", finding)
        finding["ai_assessment"] = assessment
        risk_reviews[finding["id"]] = assessment
        if assessment["status"] == "completed":
            suggested = assessment["priority"]
            if _RISK_ORDER[suggested] < _RISK_ORDER[finding["risk_level"]]:
                finding["review_priority"] = suggested
    ctx.state["ai_risk"] = risk_reviews
    ctx.save("risk_ai.json", risk_reviews)

    # -------------------------------------------------------------------------
    # Update ctx.state so the report generator can read processed findings
    # -------------------------------------------------------------------------
    ctx.state["processed_findings"] = processed
    ctx.state["skipped_findings"] = skipped

    summary = {
        "total_input":   len(raw_findings),
        "total_valid":   len(processed),
        "total_skipped": len(skipped),
        "risk_counts":   risk_counts,
        "ai_available": bool(groq_key()),
        "ai_attempted": len(risk_reviews),
        "ai_reviewed": sum(item["status"] == "completed" for item in risk_reviews.values()),
    }

    output = {
        "processed": processed,
        "skipped":   skipped,
        "summary":   summary,
    }

    ctx.save("evidence_risk.json", output)
    ctx.note(
        AGENT,
        f"Done. valid={len(processed)}, skipped={len(skipped)}, "
        f"risk_counts={risk_counts}",
    )
