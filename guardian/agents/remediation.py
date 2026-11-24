import json
import hashlib
import re
from pathlib import Path

from groq import Groq

from guardian.agents.base import RunContext
from guardian.secrets import groq_key, groq_model

AGENT = "remediation"


def _patch_hash(component: str, target_version: str) -> str:
    """Create a simple hash as proof of this proposal."""
    content = f"{component}->{target_version}"
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()[:16]


def _confidence_score(item: dict, proposal: dict) -> dict:
    """Calculate confidence score for this remediation proposal."""
    score = 0
    reasons = []

    # Fix version exists in Grype database
    if proposal.get("target_version"):
        score += 40
        reasons.append("fix version confirmed by Grype CVE database")

    # Risk score from Person 1 (scale 0-100 to 0-30)
    risk_score = item.get("risk_score", 0)
    risk_points = int((risk_score / 100) * 30)
    score += risk_points
    reasons.append(f"risk score {risk_score}/100 from risk assessment agent")

    # Direct dependency is easier to fix with higher confidence
    if item.get("ownership", {}).get("direct"):
        score += 20
        reasons.append("direct dependency - straightforward to upgrade")
    else:
        reasons.append("transitive dependency - upgrade via parent package")

    # Multiple scanners agree increases confidence
    scanners = item.get("scanners", [])
    if len(scanners) >= 2:
        score += 10
        reasons.append("multiple scanners confirm this vulnerability")

    # No fix available reduces confidence
    if not proposal.get("target_version"):
        score -= 40
        reasons.append("no fix version available - manual review needed")

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
    """Ask Groq LLM to write a human readable explanation.
    LLM only explains - never generates CVE IDs or versions."""
    client = Groq(api_key=groq_key())

    prompt = (
        f"You are a security advisor. "
        f"The package {item['component']} has vulnerability "
        f"{item['title']} "
        f"with severity {item['severity']} and risk score {item['risk_score']}. "
        f"Upgrading to version {target_version} fixes it. "
        f"The dependency path is: "
        f"{' -> '.join(item['ownership']['dependency_path'])}. "
        f"Write 2 sentences explaining why this upgrade is safe "
        f"and what risk it eliminates. "
        f"Do not invent any CVE IDs, versions or package names."
    )

    response = client.chat.completions.create(
        model=groq_model(),
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


def _validate_llm_output(text: str, cve_id: str) -> bool:
    """Make sure LLM did not invent CVE IDs."""
    found_ids = re.findall(r'GHSA-[\w-]+|CVE-\d{4}-\d+', text)
    for found_id in found_ids:
        if found_id.upper() != cve_id.upper():
            return False
    return True


def _build_proposal(item: dict) -> dict:
    """Build a proposal from Person 1's ranked risk item."""
    component = item["component"]

    # Some components may not have @ version separator
    if "@" in component:
        name, current_version = component.split("@", 1)
    else:
        name = component
        current_version = "unknown"

    fix = item.get("fix")
    cve_id = item["title"]
    ownership = item.get("ownership", {})
    dep_path = ownership.get("dependency_path", [])
    introduced_by = ownership.get("introduced_by", "direct dependency")
    direct = ownership.get("direct", False)
    risk_score = item.get("risk_score", 0)
    risk_level = item.get("risk_level", "unknown")
    rationale = item.get("rationale", "")
    finding_ids = item.get("finding_ids", [])
    evidence_refs = item.get("evidence_refs", [])
    unknowns = item.get("unknowns", [])

    if fix:
        return {
            "finding_id": finding_ids[0] if finding_ids else item["key"],
            "key": item["key"],
            "component": component,
            "result": "upgrade",
            "manifest_file": "package.json",
            "current_version": current_version,
            "target_version": fix,
            "command": f"npm install {name}@{fix}",
            "introduced_by": introduced_by,
            "direct": direct,
            "dependency_path": dep_path,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "rationale": rationale,
            "expected_risk_reduction": (
                f"{item['severity'].upper()} vulnerability eliminated after upgrade"
            ),
            "compatibility_concern": (
                f"Upgrade {name} from {current_version} to {fix}"
            ),
            "rollback": f"npm install {name}@{current_version}",
            "patch_hash": _patch_hash(component, fix),
            "evidence_refs": evidence_refs,
            "unknowns": unknowns,
        }
    else:
        return {
            "finding_id": finding_ids[0] if finding_ids else item["key"],
            "key": item["key"],
            "component": component,
            "result": "mitigation_only",
            "mitigation": "manual_review",
            "reason": f"No fix version available for {cve_id}",
            "introduced_by": introduced_by,
            "direct": direct,
            "dependency_path": dep_path,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "rationale": rationale,
            "rollback": None,
            "patch_hash": None,
            "evidence_refs": evidence_refs,
            "unknowns": unknowns,
        }


def run(ctx: RunContext) -> None:
    # Load risk_assessment.json from Person 1
    risk_path = ctx.run_dir / "risk_assessment.json"

    if not risk_path.exists():
        ctx.note(AGENT, "risk_assessment.json not found. Using fallback from ctx.state...")
        findings = ctx.state.get("findings", [])
        if not findings:
            ctx.note(AGENT, "No findings in state. Run vulnerability agent first.")
            return
        # Fallback: convert raw findings to basic items
        items = []
        for f in findings:
            if f.get("type") == "vulnerability":
                items.append({
                    "key": f["id"],
                    "title": f["title"],
                    "component": f["component"],
                    "severity": f["severity"],
                    "risk_score": 0,
                    "risk_level": "unrated",
                    "fix": f.get("fix"),
                    "ownership": {
                        "direct": False,
                        "dependency_path": f.get("dependency_path", []),
                        "introduced_by": "unknown",
                    },
                    "scanners": ["grype"],
                    "finding_ids": [f["id"]],
                    "evidence_refs": [],
                    "unknowns": [],
                    "rationale": "No risk assessment available",
                })
    else:
        ctx.note(AGENT, f"Loading risk_assessment.json from {risk_path}")
        risk_data = json.loads(risk_path.read_text(encoding="utf-8"))
        items = risk_data.get("items", [])
        ctx.note(AGENT, f"Loaded {len(items)} ranked items from Person 1")

    # Process CRITICAL and HIGH first
    critical_high = [
        i for i in items
        if i.get("risk_level") in ("critical", "high")
    ]
    others = [
        i for i in items
        if i.get("risk_level") not in ("critical", "high")
    ]

    ctx.note(AGENT, f"Processing {len(critical_high)} CRITICAL/HIGH items first")
    ctx.note(AGENT, f"Then {len(others)} MEDIUM/LOW items")

    proposals = []

    for item in critical_high + others:
        try:
            proposal = _build_proposal(item)
        except Exception as e:
            ctx.note(AGENT, f"Skipping {item.get('key', '?')}: {e}")
            continue

        # Add confidence score
        confidence = _confidence_score(item, proposal)
        proposal["confidence_score"] = confidence["score"]
        proposal["confidence_label"] = confidence["label"]
        proposal["confidence_reasons"] = confidence["reasons"]

        # Ask Groq LLM for explanation only for upgrade proposals
        if proposal["result"] == "upgrade":
            try:
                explanation = _ask_groq(item, proposal["target_version"])
                if not explanation or len(explanation.strip()) == 0:
                    proposal["llm_explanation"] = "LLM returned empty response."
                    ctx.note(
                        AGENT,
                        f"LLM empty for {proposal['finding_id']} "
                        f"({item['component']})"
                    )
                elif _validate_llm_output(explanation, item["title"]):
                    proposal["llm_explanation"] = explanation
                    ctx.note(
                        AGENT,
                        f"LLM explanation added for {proposal['finding_id']} "
                        f"({item['component']})"
                    )
                else:
                    proposal["llm_explanation"] = "LLM output failed validation."
                    ctx.note(
                        AGENT,
                        f"LLM validation failed for {proposal['finding_id']} "
                        f"({item['component']})"
                    )
            except Exception as e:
                proposal["llm_explanation"] = "LLM unavailable. See raw facts."
                ctx.note(
                    AGENT,
                    f"LLM error for {proposal['finding_id']} "
                    f"({item['component']}): {e}"
                )

        proposals.append(proposal)
        ctx.note(
            AGENT,
            f"{proposal['finding_id']} | {item['component']} | "
            f"risk:{item.get('risk_score', '?')} | "
            f"confidence:{confidence['score']}% ({confidence['label']}) | "
            f"{proposal['result']} -> fix: {proposal.get('target_version', 'N/A')}"
        )

    ctx.save("proposals.json", proposals)
    ctx.note(AGENT, f"Saved {len(proposals)} proposals to proposals.json")