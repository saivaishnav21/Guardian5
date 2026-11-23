import difflib
import json
import subprocess
from pathlib import Path
from typing import Mapping

from guardian.agents.base import RunContext
from guardian.schemas import Finding


AGENT = "Suspicious Change Agent"
TAMPERED_BRANCH = "guardian-demo-tampered"
LIFECYCLE_SCRIPTS = {
    "preinstall", "install", "postinstall", "prepublish", "prepare",
}
POPULAR_PACKAGES = {
    "lodash", "express", "react", "react-dom", "axios", "chalk",
    "commander", "dotenv", "request", "body-parser", "cors",
    "mongoose", "morgan", "nodemon", "typescript", "webpack",
    "babel", "passport", "rxjs", "next", "redux", "fastify",
    "helmet", "ws", "node-fetch", "bcrypt",
}


def _run_git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
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
    return difflib.SequenceMatcher(
        None, left.lower(), right.lower()
    ).ratio()


def detect_typosquat(package_name: str) -> dict | None:
    normalized = package_name.lower().strip()
    if "/" in normalized and normalized.startswith("@"):
        normalized = normalized.rsplit("/", 1)[-1]
    if normalized in POPULAR_PACKAGES:
        return None

    target = max(
        POPULAR_PACKAGES,
        key=lambda popular: _similarity(normalized, popular),
    )
    score = _similarity(normalized, target)
    if score < 0.87:
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

    dependencies = {}
    if isinstance(package_json, Mapping):
        if isinstance(package_json.get("dependencies"), Mapping):
            dependencies.update(package_json["dependencies"])
        if isinstance(package_json.get("devDependencies"), Mapping):
            dependencies.update(package_json["devDependencies"])

    for name in dependencies:
        match = detect_typosquat(str(name))
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
                    "branch": TAMPERED_BRANCH,
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
                    "branch": TAMPERED_BRANCH,
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
                    "branch": TAMPERED_BRANCH,
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
                    "branch": TAMPERED_BRANCH,
                },
            ))

    fetch = _run_git(repo, "fetch", "origin",
                     f"{TAMPERED_BRANCH}:refs/remotes/origin/{TAMPERED_BRANCH}",
                     "--depth=1")
    if fetch.returncode == 0:
        base = _base_branch(repo)
        compare = f"origin/{TAMPERED_BRANCH}"
        base_package = _json_at_revision(repo, base, "package.json")
        current_package = _json_at_revision(repo, compare, "package.json")
        base_lockfile = _json_at_revision(repo, base, "package-lock.json")
        current_lockfile = _json_at_revision(repo, compare, "package-lock.json")

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
                        "branch": TAMPERED_BRANCH,
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
                        "branch": TAMPERED_BRANCH,
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
                            "branch": TAMPERED_BRANCH,
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
                            "branch": TAMPERED_BRANCH,
                        },
                    ))

    for finding in findings:
        ctx.add_finding(finding)

    ctx.state["suspicious"] = {
        "finding_count": len(findings),
        "tampered_branch": TAMPERED_BRANCH,
    }
    ctx.save("suspicious.json", ctx.state["suspicious"])
    ctx.note(
        AGENT,
        f"static analysis complete: {len(findings)} suspicious finding(s)",
    )
