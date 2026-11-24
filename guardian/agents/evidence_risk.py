"""
Evidence & Risk Agent  –  guardian/agents/evidence_risk.py
==========================================================
Person 5 contribution.

Responsibilities
----------------
1. Read raw findings produced by earlier agents from ctx.state["findings"].
2. Validate every finding: required fields, ID format, evidence dict non-empty.
3. Assign a transparent risk_level based on severity + evidence quality.
4. Enrich findings with concise remediation recommendations.
5. Optionally call Groq (llama-3.3-70b-versatile) to explain findings in plain
   language (never to invent CVEs, versions, or new evidence).
6. Save processed output via ctx.save().

Design rules (hallucination prevention)
----------------------------------------
- AI is NEVER the source of risk decisions; it only produces human-readable prose.
- All risk levels are computed deterministically before the AI call.
- AI output is checked for new CVE IDs; other claims require human review.
- If the API key is absent or the call fails, the deterministic fallback is used.
"""

from __future__ import annotations

import json
import os
import re
import textwrap
from typing import Any

from guardian.agents.base import RunContext
from guardian.secrets import groq_key, groq_model

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
# Optional Groq AI explanation  (prose only, never source of risk data)
# ---------------------------------------------------------------------------

def _build_ai_prompt(finding: dict) -> str:
    evidence = finding.get("evidence") or {}
    safe_evidence = {
        key: evidence[key] for key in (
            "tool", "vulnerability_id", "cve_ids", "severity", "purl",
            "fixed_versions", "file", "line"
        ) if key in evidence
    }
    safe_finding = {
        key: finding.get(key) for key in ("id", "type", "title", "component", "severity", "risk_level")
    }
    safe_finding["evidence"] = safe_evidence
    return textwrap.dedent(f"""
        You are a software supply-chain security analyst.
        Provide a concise, plain-language explanation (2–4 sentences) of the
        following security finding for a developer audience.

        STRICT RULES:
        - Do NOT invent or modify CVE IDs, version numbers, or package names.
        - Do NOT introduce new evidence or change the risk level.
        - Explain only what the evidence already shows.
        - Return plain text, no markdown.

        Finding JSON:
        {json.dumps(safe_finding, indent=2, default=str)}
    """).strip()


def _ai_explanation(finding: dict) -> str | None:
    """
    Call Groq (llama-3.3-70b-versatile) for a plain-language explanation.
    Returns None if the key is absent, the call fails, or output looks fabricated.
    """
    api_key = groq_key()
    if not api_key:
        return None

    try:
        from groq import Groq  # optional dependency
        client = Groq(api_key=api_key, timeout=15.0, max_retries=0)
        response = client.chat.completions.create(
            model=groq_model(),
            max_completion_tokens=256,
            messages=[{"role": "user", "content": _build_ai_prompt(finding)}],
        )
        text = response.choices[0].message.content.strip()

        # Hallucination guard: reject if AI introduces new CVE IDs
        original_cves = set(re.findall(r"CVE-\d{4}-\d+", json.dumps(finding)))
        output_cves   = set(re.findall(r"CVE-\d{4}-\d+", text))
        new_cves = output_cves - original_cves
        if new_cves:
            return None  # silently discard fabricated references

        return text
    except Exception:  # noqa: BLE001
        return None


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
        # Optional AI prose explanation
        # -----------------------------------------------------------------
        f["ai_explanation"] = None

        # -----------------------------------------------------------------
        # Tracking metadata
        # -----------------------------------------------------------------
        f["_original_risk_level"] = original_risk
        f["_processed_by"]        = AGENT

        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        processed.append(f)
        ctx.note(AGENT, f"  [{f['id']}] {f['title'][:60]} -> risk={risk_level}")

    for finding in sorted(processed, key=lambda item: (
        _RISK_ORDER.get(item["risk_level"], 99), item["id"]
    ))[:5]:
        finding["ai_explanation"] = _ai_explanation(finding)

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
