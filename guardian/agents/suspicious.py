import json
import os
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Mapping

from guardian.agents.base import RunContext
from guardian.schemas import Finding
from guardian.secrets import scanner_env

try:
    from rapidfuzz.fuzz import WRatio
except ImportError:
    WRatio = None


AGENT = "Suspicious Change Agent"
LIFECYCLE_SCRIPTS = {
    "preinstall", "install", "postinstall", "prepublish", "prepare",
}
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


def _groq_api_key() -> str:
    configured = os.getenv("GROQ_API_KEY", "").strip()
    if configured:
        return configured

    source = Path(__file__).resolve()
    candidates = (
        source.parents[2] / "api.txt",
        source.parents[3] / "api.txt",
    )
    for path in candidates:
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
    return ""


def enrich_findings_with_groq(findings: list[Finding]) -> list[Finding]:
    """Use Groq only to explain/prioritize existing deterministic findings."""
    api_key = _groq_api_key()
    if not api_key or not findings:
        return findings

    prompt_payload = [
        {
            "title": finding.title,
            "component": finding.component,
            "severity": finding.severity,
            "evidence": finding.evidence,
        }
        for finding in findings
    ]
    prompt = (
        "You enrich supply-chain security findings. "
        "Use only the provided evidence. Do not claim facts not present. "
        "Return a JSON array with one object per input finding containing "
        "risk_level ('low', 'medium', 'high', or 'critical'), "
        "ai_summary, and ai_recommended_action.\n"
        f"Findings: {json.dumps(prompt_payload, ensure_ascii=False)}"
    )
    body = json.dumps({
        "model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "Return only valid JSON. Be conservative and evidence-grounded."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }).encode("utf-8")

    request = urllib.request.Request(
        GROQ_API_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response_data = json.loads(response.read().decode("utf-8"))
        content = response_data["choices"][0]["message"]["content"]
        enrichment = json.loads(content)
        if isinstance(enrichment, dict):
            values = enrichment.get("findings", enrichment)
            if isinstance(values, dict):
                values = list(values.values())
        else:
            values = enrichment
        if not isinstance(values, list):
            return findings
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, KeyError, TimeoutError, OSError):
        return findings

    for finding, item in zip(findings, values):
        if not isinstance(item, dict):
            continue
        risk = str(item.get("risk_level", "")).lower()
        if risk in {"low", "medium", "high", "critical"}:
            finding.risk_level = risk
        summary = item.get("ai_summary")
        action = item.get("ai_recommended_action")
        finding.notes.append(str(summary)) if summary else None
        if action:
            finding.evidence["groq_recommended_action"] = str(action)
    return findings


def _run_git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
        env=scanner_env(),
    )


def _read_json(path: Path) -> Mapping | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def _package_entries(lockfile: Mapping) -> dict[str, Mapping]:
    entries: dict[str, Mapping] = {}
    packages = lockfile.get("packages")
    if isinstance(packages, Mapping):
        for location, details in packages.items():
            if not isinstance(details, Mapping):
                continue
            name = details.get("name")
            if not name and isinstance(location, str) and "node_modules/" in location:
                name = location.rsplit("node_modules/", 1)[-1]
            if name:
                entries[str(name)] = details
    else:
        dependencies = lockfile.get("dependencies")
        if isinstance(dependencies, Mapping):
            entries.update(
                (str(name), details)
                for name, details in dependencies.items()
                if isinstance(details, Mapping)
            )
    return entries


def _similarity(left: str, right: str) -> float:
    if WRatio is not None:
        return float(WRatio(left, right)) / 100.0
    return 0.0


def detect_typosquat(
    package_name: str,
    candidates: set[str] | list[str] | tuple[str, ...] | None = None,
    threshold: float = 0.87,
) -> dict | None:
    normalized = package_name.lower().strip()
    if "/" in normalized and normalized.startswith("@"):
        normalized = normalized.rsplit("/", 1)[-1]
    candidates = set(candidates or [])
    candidates = {
        str(candidate).lower().strip().rsplit("/", 1)[-1]
        for candidate in candidates
    }
    if not candidates or normalized in candidates:
        return None

    target = max(
        candidates,
        key=lambda candidate: _similarity(normalized, candidate),
    )
    score = _similarity(normalized, target)
    if score < threshold:
        return None

    return {
        "target": target,
        "score": round(score, 2),
    }


def _finding(
    index: int,
    package: str,
    title: str,
    severity: str,
    evidence: dict,
    dependency_path: list[str] | None = None,
) -> Finding:
    return Finding(
        id=f"SUSP-{index:03d}",
        type="suspicious_change",
        title=title,
        component=package,
        dependency_path=dependency_path or [],
        evidence=evidence,
        severity=severity,
        source_agent=AGENT,
    )


def _json_at_revision(repo: Path, revision: str, filename: str) -> Mapping | None:
    result = _run_git(repo, "show", f"{revision}:{filename}")
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, Mapping) else None


def _base_branch(repo: Path) -> str:
    for branch in ("main", "master"):
        result = _run_git(repo, "rev-parse", "--verify", f"origin/{branch}")
        if result.returncode == 0:
            return f"origin/{branch}"
    result = _run_git(repo, "symbolic-ref", "--short", "HEAD")
    if result.returncode == 0:
        return result.stdout.strip()
    return "HEAD"


def _tampered_branch(repo: Path) -> str:
    configured = os.getenv("GUARDIAN_TAMPERED_BRANCH", "").strip()
    if configured:
        return configured
    result = _run_git(
        repo,
        "config",
        "--get",
        "guardian.tamperedBranch",
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return "guardian-demo-tampered"


def detect_install_scripts(
    lockfile: Mapping,
    package_json: Mapping | None = None,
) -> list[dict]:
    """Return install lifecycle findings from package and lockfile data."""
    findings = []

    if isinstance(package_json, Mapping):
        scripts = package_json.get("scripts")
        if isinstance(scripts, Mapping):
            lifecycle = sorted(set(scripts) & LIFECYCLE_SCRIPTS)
            if lifecycle:
                findings.append({
                    "type": "suspicious_change",
                    "package": str(package_json.get("name") or "root-package"),
                    "severity": "high",
                    "evidence": {
                        "what_changed": (
                            f"Lifecycle scripts declared: {', '.join(lifecycle)}"
                        ),
                        "where": "package.json",
                        "why_suspicious": (
                            "Install lifecycle scripts can execute code during setup"
                        ),
                        "scripts": lifecycle,
                    },
                })

    for name, details in _package_entries(lockfile).items():
        scripts = details.get("scripts")
        lifecycle = (
            sorted(set(scripts) & LIFECYCLE_SCRIPTS)
            if isinstance(scripts, Mapping)
            else []
        )
        if details.get("hasInstallScript") or lifecycle:
            findings.append({
                "type": "suspicious_change",
                "package": name,
                "severity": "high",
                "evidence": {
                    "what_changed": "Package has install-time lifecycle behavior",
                    "where": "package-lock.json",
                    "why_suspicious": (
                        "hasInstallScript is true or an install lifecycle script "
                        "is declared"
                    ),
                    "scripts": lifecycle,
                },
            })
    return findings


def detect_non_registry_resolutions(lockfile: Mapping) -> list[dict]:
    """Return findings for git, HTTP, and direct lockfile resolutions."""
    findings = []
    for name, details in _package_entries(lockfile).items():
        values = (
            details.get("resolved"),
            details.get("from"),
            details.get("version"),
        )
        resolutions = [
            str(value) for value in values
            if isinstance(value, str) and value
        ]
        outside_registry = [
            value for value in resolutions
            if value.startswith((
                "git+", "git://", "github:", "http://", "https://",
                "ssh://", "file:", "github.com/",
            ))
            and "/-/" not in value
        ]
        if outside_registry:
            findings.append({
                "type": "suspicious_change",
                "package": name,
                "severity": "high",
                "evidence": {
                    "what_changed": "Lockfile has a repository or direct URL resolution",
                    "where": "package-lock.json",
                    "why_suspicious": (
                        "The dependency is not resolved by normal registry metadata"
                    ),
                    "resolutions": outside_registry,
                },
            })
    return findings


def lockfile_diff(before: Mapping, after: Mapping) -> list[dict]:
    """Return package additions and version, resolved URL, and integrity changes."""
    findings = []
    before_entries = _package_entries(before)
    after_entries = _package_entries(after)

    for name in sorted(set(after_entries) - set(before_entries)):
        findings.append({
            "type": "suspicious_change",
            "package": name,
            "severity": "medium",
            "evidence": {
                "what_changed": f"Lockfile dependency {name} was added",
                "where": "package-lock.json",
                "why_suspicious": "Package is absent from the base lockfile",
                "old_value": None,
                "new_value": after_entries[name].get("version"),
            },
        })

    for name in sorted(set(before_entries) & set(after_entries)):
        old = before_entries[name]
        new = after_entries[name]
        if old.get("integrity") != new.get("integrity"):
            findings.append({
                "type": "suspicious_change",
                "package": name,
                "severity": "high",
                "evidence": {
                    "what_changed": f"Integrity hash for {name} changed",
                    "where": "package-lock.json",
                    "why_suspicious": "The package digest differs from the base lockfile",
                    "old_value": old.get("integrity"),
                    "new_value": new.get("integrity"),
                },
            })
        if old.get("resolved") != new.get("resolved"):
            findings.append({
                "type": "suspicious_change",
                "package": name,
                "severity": "high",
                "evidence": {
                    "what_changed": f"Resolution for {name} changed",
                    "where": "package-lock.json",
                    "why_suspicious": "The package source differs from the base lockfile",
                    "old_value": old.get("resolved"),
                    "new_value": new.get("resolved"),
                },
            })
    return findings


def run(ctx: RunContext) -> None:
    recon = ctx.state.get("recon", {})
    target_dir = recon.get("target_dir")
    if not target_dir:
        ctx.note(AGENT, "Recon target directory is unavailable")
        return

    repo = Path(target_dir)
    package_path = repo / "package.json"
    lockfile_path = repo / "package-lock.json"
    package_json = _read_json(package_path) or {}
    lockfile = _read_json(lockfile_path) or {}
    findings: list[Finding] = []
    tampered_branch = _tampered_branch(repo)
    base = _base_branch(repo)
    base_package = _json_at_revision(repo, base, "package.json")
    base_lockfile = _json_at_revision(repo, base, "package-lock.json")
    dependencies = {}
    if isinstance(package_json, Mapping):
        if isinstance(package_json.get("dependencies"), Mapping):
            dependencies.update(package_json["dependencies"])
        if isinstance(package_json.get("devDependencies"), Mapping):
            dependencies.update(package_json["devDependencies"])

    candidate_names = set()
    if base_package:
        for section in ("dependencies", "devDependencies"):
            values = base_package.get(section)
            if isinstance(values, Mapping):
                candidate_names.update(str(name) for name in values)
    if base_lockfile:
        candidate_names.update(_package_entries(base_lockfile))

    for name in dependencies:
        match = detect_typosquat(str(name), candidates=candidate_names)
        if match:
            findings.append(_finding(
                len(findings) + 1,
                str(name),
                "Potential typosquatted npm dependency",
                "high",
                {
                    "what_changed": f"Dependency {name} was found",
                    "where": "package.json",
                    "why_suspicious": (
                        f"Package name is {match['score']} similar to "
                        f"{match['target']}"
                    ),
                    "similar_to": match["target"],
                    "confidence": match["score"],
                    "branch": base,
                },
            ))

    scripts = package_json.get("scripts")
    if isinstance(scripts, Mapping):
        found_scripts = sorted(set(scripts) & LIFECYCLE_SCRIPTS)
        if found_scripts:
            findings.append(_finding(
                len(findings) + 1,
                str(package_json.get("name") or "root-package"),
                "Install lifecycle script detected",
                "high",
                {
                    "what_changed": f"Lifecycle scripts declared: {', '.join(found_scripts)}",
                    "where": "package.json",
                    "why_suspicious": (
                        "Install lifecycle scripts can execute code during setup"
                    ),
                    "scripts": found_scripts,
                    "branch": base,
                },
            ))

    for name, details in _package_entries(lockfile).items():
        values = (
            details.get("resolved"),
            details.get("from"),
            details.get("version"),
        )
        resolutions = [
            str(value) for value in values
            if isinstance(value, str) and value
        ]
        outside_registry = [
            value for value in resolutions
            if value.startswith((
                "git+", "git://", "github:", "http://", "https://",
                "ssh://", "file:", "github.com/",
            ))
            and "/-/" not in value
        ]
        if outside_registry:
            findings.append(_finding(
                len(findings) + 1,
                name,
                "Dependency resolved outside npm registry",
                "high",
                {
                    "what_changed": "Lockfile has a repository or direct URL resolution",
                    "where": "package-lock.json",
                    "why_suspicious": (
                        "The dependency is not resolved by normal registry metadata"
                    ),
                    "resolutions": outside_registry,
                    "branch": base,
                },
            ))

        scripts = details.get("scripts")
        lifecycle = (
            sorted(set(scripts) & LIFECYCLE_SCRIPTS)
            if isinstance(scripts, Mapping)
            else []
        )
        if details.get("hasInstallScript") or lifecycle:
            findings.append(_finding(
                len(findings) + 1,
                name,
                "Locked package declares install-time behavior",
                "high",
                {
                    "what_changed": "Package has install-time lifecycle behavior",
                    "where": "package-lock.json",
                    "why_suspicious": (
                        "hasInstallScript is true or an install lifecycle script "
                        "is declared"
                    ),
                    "scripts": lifecycle,
                    "branch": base,
                },
            ))

    fetch = _run_git(repo, "fetch", "origin",
                     f"{tampered_branch}:refs/remotes/origin/{tampered_branch}",
                     "--depth=1")
    if fetch.returncode == 0:
        base = _base_branch(repo)
        compare = f"origin/{tampered_branch}"
        current_package = _json_at_revision(repo, compare, "package.json")
        current_lockfile = _json_at_revision(repo, compare, "package-lock.json")
        branch_available = current_package is not None or current_lockfile is not None
    else:
        local = _run_git(repo, "rev-parse", "--verify", tampered_branch)
        if local.returncode == 0:
            compare = tampered_branch
            current_package = _json_at_revision(repo, compare, "package.json")
            current_lockfile = _json_at_revision(repo, compare, "package-lock.json")
            branch_available = current_package is not None or current_lockfile is not None
        else:
            branch_available = False

    if branch_available:
        if base_package is not None and current_package is not None:
            before = {}
            after = {}
            for section in ("dependencies", "devDependencies"):
                if isinstance(base_package.get(section), Mapping):
                    before.update(base_package[section])
                if isinstance(current_package.get(section), Mapping):
                    after.update(current_package[section])
            for name in sorted(set(after) - set(before)):
                findings.append(_finding(
                    len(findings) + 1,
                    name,
                    "Unexpected dependency added on tampered branch",
                    "medium",
                    {
                        "what_changed": f"Dependency {name} was added",
                        "where": "package.json",
                        "why_suspicious": "Dependency is absent from the base branch",
                        "old_value": None,
                        "new_value": after[name],
                        "branch": tampered_branch,
                    },
                ))

        if base_lockfile is not None and current_lockfile is not None:
            before_entries = _package_entries(base_lockfile)
            after_entries = _package_entries(current_lockfile)

            for name in sorted(set(after_entries) - set(before_entries)):
                findings.append(_finding(
                    len(findings) + 1,
                    name,
                    "Unexpected lockfile dependency added",
                    "medium",
                    {
                        "what_changed": f"Lockfile dependency {name} was added",
                        "where": "package-lock.json",
                        "why_suspicious": "Package is absent from the base lockfile",
                        "old_value": None,
                        "new_value": after_entries[name].get("version"),
                        "branch": tampered_branch,
                    },
                ))

            for name in sorted(set(before_entries) & set(after_entries)):
                before = before_entries[name]
                after = after_entries[name]
                if before.get("integrity") != after.get("integrity"):
                    findings.append(_finding(
                        len(findings) + 1,
                        name,
                        "Lockfile integrity hash modified",
                        "high",
                        {
                            "what_changed": f"Integrity hash for {name} changed",
                            "where": "package-lock.json",
                            "why_suspicious": (
                                "The package digest differs from the base branch"
                            ),
                            "old_value": before.get("integrity"),
                            "new_value": after.get("integrity"),
                            "branch": tampered_branch,
                        },
                    ))
                if before.get("resolved") != after.get("resolved"):
                    findings.append(_finding(
                        len(findings) + 1,
                        name,
                        "Lockfile resolution source modified",
                        "high",
                        {
                            "what_changed": f"Resolution for {name} changed",
                            "where": "package-lock.json",
                            "why_suspicious": (
                                "The package source differs from the base branch"
                            ),
                            "old_value": before.get("resolved"),
                            "new_value": after.get("resolved"),
                            "branch": tampered_branch,
                        },
                    ))

    for finding in findings:
        ctx.add_finding(finding)

    ctx.state["suspicious"] = {
        "status": "completed_static",
        "branch_comparison": "completed" if branch_available else "not_available",
        "finding_count": len(findings),
        "tampered_branch": tampered_branch,
    }
    ctx.save("suspicious.json", ctx.state["suspicious"])
    ctx.note(
        AGENT,
        f"static analysis complete: {len(findings)} suspicious finding(s)",
    )
