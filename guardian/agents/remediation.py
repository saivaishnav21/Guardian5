import json
import re
from pathlib import Path

from guardian.agents.base import RunContext
from guardian.approval_gate import load_policy, trial_route
from guardian.secrets import groq_key, groq_model

AGENT = "Remediation Proposal Agent"
MAX_AI_EXPLANATIONS = 3
NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$", re.I)
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+-]*$")


def _npm_package(component: str) -> tuple[str, str] | None:
    """Parse regular and scoped npm component names without guessing an ecosystem."""
    name, separator, version = str(component).rpartition("@")
    if separator and NPM_NAME_RE.fullmatch(name) and VERSION_RE.fullmatch(version):
        return name, version
    return None


def _fix_version(value) -> str | None:
    candidates = value if isinstance(value, list) else [value]
    for candidate in candidates:
        if isinstance(candidate, str) and VERSION_RE.fullmatch(candidate.strip()):
            return candidate.strip()
    return None


def _direct_manifest(ctx: RunContext, name: str) -> str | None:
    """Locate the one npm manifest that declares this direct dependency."""
    recon = ctx.state.get("recon", {})
    if not recon.get("target_dir"):
        return None
    target = Path(recon.get("target_dir") or "")
    matches = []
    for relative in recon.get("manifests", []):
        if Path(relative).name != "package.json":
            continue
        path = (target / relative).resolve()
        if not path.is_relative_to(target.resolve()):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if any(name in (data.get(section) or {}) for section in ("dependencies", "devDependencies")
               if isinstance(data.get(section), dict)):
            matches.append(relative)
    return matches[0] if len(matches) == 1 else None


def _confidence_score(item: dict, proposal: dict) -> dict:
    """Calculate confidence score for this remediation proposal."""
    score = 0
    reasons = []

    # Fix version exists in Grype database
    if proposal.get("target_version"):
        score += 40
        reasons.append("fix version confirmed by Grype CVE database")

    # Confidence describes proposal evidence, not the severity of the finding.
    if proposal.get("manifest_file"):
        score += 20
        reasons.append("direct dependency found in one manifest")
    if proposal.get("result") == "upgrade":
        score += 10
        reasons.append("bounded npm change proposed; compatibility still untested")

    # Multiple scanners agree increases confidence
    scanners = item.get("scanners", [])
    if len(scanners) >= 2:
        score += 10
        reasons.append("multiple scanners confirm this vulnerability")

    if proposal.get("result") != "upgrade":
        score = min(score, 30)
        reasons.append("manual work is needed before a candidate can be tested")

    # Cap between 0 and 100
    score = max(0, min(100, score))

    # Label
    if score >= 70:
        label = "high"
    elif score >= 40:
        label = "medium"
    else:
        label = "low"

    return {
        "score": score,
        "label": label,
        "reasons": reasons
    }


def _ask_groq(item: dict, target_version: str) -> str:
    """Ask for bounded advisory text; the model never decides whether to apply a fix."""
    from groq import Groq

    client = Groq(api_key=groq_key(), timeout=15.0, max_retries=0)

    prompt = (
        f"You are a security advisor. "
        f"The package {item['component']} has vulnerability "
        f"{item['title']} "
        f"with severity {item['severity']} and risk score {item['risk_score']}. "
        f"Upgrading to version {target_version} fixes it. "
        f"The dependency path is: "
        f"{' -> '.join(item['ownership']['dependency_path'])}. "
        "Write 2 sentences explaining the proposed change and what remains "
        "unverified. Do not claim the upgrade is safe or that the risk is eliminated. "
        "Do not invent CVE IDs, versions, package names, or test results."
    )

    response = client.chat.completions.create(
        model=groq_model(),
        max_completion_tokens=350,
        temperature=0,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


def _validate_llm_output(text: str, item: dict, target_version: str) -> bool:
    """Reject identifiers and versions absent from the proposal evidence."""
    ids = re.compile(r'GHSA-[\w-]+|CVE-\d{4}-\d+', re.I)
    versions = re.compile(r'\b\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?\b')
    known = f"{item.get('title', '')} {item.get('key', '')} {item.get('component', '')} {target_version}"
    return ({value.upper() for value in ids.findall(text)}
            <= {value.upper() for value in ids.findall(known)}
            and set(versions.findall(text)) <= set(versions.findall(known)))


def _build_proposal(ctx: RunContext, item: dict) -> dict:
    """Turn ranked evidence into a bounded candidate or an explicit manual case."""
    component = str(item.get("component") or "")
    package = _npm_package(component)
    fix = _fix_version(item.get("fix"))
    ownership = item.get("ownership") or {}
    direct = ownership.get("direct") is True
    ecosystems = ctx.state.get("recon", {}).get("ecosystems", [])
    npm = "npm" in ecosystems and package is not None
    manifest = _direct_manifest(ctx, package[0]) if npm and direct and fix else None
    actionable = item.get("type") == "vulnerability" and bool(fix and manifest)
    result = "upgrade" if actionable else "manual_review" if fix else "mitigation_only"
    reason = None
    if result == "manual_review":
        reason = ("Transitive dependency: inspect the direct owner's compatible version."
                  if not direct else "No unique supported manifest or package version was found.")
    elif result == "mitigation_only":
        reason = "The scanner did not record a supported fixed version."

    finding_ids = item.get("finding_ids") or []
    proposal = {
        "schema_version": 1,
        "repo_url": ctx.repo_url,
        "baseline_commit": ctx.state.get("recon", {}).get("commit"),
        "finding_id": finding_ids[0] if finding_ids else item.get("key"),
        "finding_ids": finding_ids,
        "key": item.get("key"),
        "component": component,
        "result": result,
        "reason": reason,
        "ecosystem": "npm" if npm else "unknown",
        "manifest_file": manifest,
        "current_version": package[1] if package else None,
        "target_version": fix,
        "command": (f"npm install --package-lock-only --ignore-scripts {package[0]}@{fix}"
                    if actionable else None),
        "working_directory": str(Path(manifest).parent) if manifest else None,
        "introduced_by": ownership.get("introduced_by"),
        "direct": direct,
        "dependency_path": ownership.get("dependency_path") or [],
        "risk_score": item.get("risk_score"),
        "risk_level": item.get("risk_level"),
        "rationale": item.get("rationale"),
        "expected_risk_reduction": (
            "Potentially removes this finding if build, tests, and rescan confirm it."
            if actionable else None
        ),
        "compatibility_concern": "Compatibility has not been tested." if actionable else None,
        "constraint_check": "not_run",
        "rollback": "Restore the manifest and lockfile from the baseline commit." if actionable else None,
        "patch_path": None,
        "patch_sha256": None,
        "patch_hash": None,
        "evidence_refs": item.get("evidence_refs") or [],
        "unknowns": list(item.get("unknowns") or []) + (["compatibility not tested"] if actionable else []),
    }
    return proposal


def run(ctx: RunContext) -> None:
    """Produce one reviewable proposal per ranked item, without changing the target."""
    risk_path = ctx.run_dir / "risk_assessment.json"
    if not risk_path.exists():
        ctx.state["remediation"] = {"status": "blocked_missing_risk_assessment", "count": 0}
        ctx.save("proposals.json", [])
        ctx.note(AGENT, "risk_assessment.json is missing; proposals were not generated")
        return

    risk_data = json.loads(risk_path.read_text(encoding="utf-8"))
    items = risk_data.get("items", [])
    if not isinstance(items, list):
        raise ValueError("risk_assessment.json items must be a list")
    proposals = []
    policy = load_policy()
    ai_calls = 0
    ai_available = bool(groq_key())
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            proposal = _build_proposal(ctx, item)
        except (KeyError, TypeError, ValueError) as exc:
            ctx.note(AGENT, f"Skipping malformed risk item {item.get('key', '?')}: {type(exc).__name__}")
            continue
        confidence = _confidence_score(item, proposal)
        proposal["confidence_score"] = confidence["score"]
        proposal["confidence_label"] = confidence["label"]
        proposal["confidence_reasons"] = confidence["reasons"]
        proposal["trial_route"] = trial_route(proposal, policy)
        proposal["llm_explanation_status"] = "not_requested"
        if proposal["result"] == "upgrade" and ai_available and ai_calls < MAX_AI_EXPLANATIONS:
            ai_calls += 1
            try:
                explanation = _ask_groq(item, proposal["target_version"])
                if explanation and _validate_llm_output(explanation, item, proposal["target_version"]):
                    proposal["llm_explanation"] = explanation.strip()[:500]
                    proposal["llm_explanation_status"] = "completed_unverified"
                else:
                    proposal["llm_explanation_status"] = "invalid_response"
            except Exception as exc:
                proposal["llm_explanation_status"] = type(exc).__name__
                if type(exc).__name__ == "RateLimitError":
                    ai_available = False
        proposals.append(proposal)

    path = ctx.save("proposals.json", proposals)
    counts = {status: sum(p["result"] == status for p in proposals)
              for status in ("upgrade", "manual_review", "mitigation_only")}
    ctx.state["remediation"] = {"status": "completed", "path": str(path),
                                 "count": len(proposals), "by_result": counts,
                                 "ai_calls": ai_calls}
    ctx.note(AGENT, f"Saved {len(proposals)} proposals to {path}: {counts}; AI calls={ai_calls}")
