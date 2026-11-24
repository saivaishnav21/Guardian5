"""Static Docker/CI inspection with an optional local-image Trivy scan."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from guardian.agents.base import RunContext
from guardian.schemas import Finding
from guardian.secrets import scanner_env

AGENT = "Container & CI Agent"
PINNED_ACTION = re.compile(r"^[^@]+@[0-9a-fA-F]{40}$")


def _lines(path: Path):
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.strip()
        if line and not line.startswith("#"):
            yield number, line


def _scan_image(ctx: RunContext, image_ref: str, first_id: int) -> tuple[str, list[Finding], str | None]:
    trivy = shutil.which("trivy")
    if not trivy and os.environ.get("LOCALAPPDATA"):
        winget_link = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "WinGet" / "Links" / "trivy.exe"
        if winget_link.is_file():
            trivy = str(winget_link)
    if not trivy:
        return "not_run_missing_trivy", [], "Trivy is not installed"
    output = ctx.run_dir / "trivy_image.json"
    try:
        result = subprocess.run(
            [trivy, "image", "--image-src", "docker", "--format", "json",
             "--output", str(output), image_ref],
            capture_output=True, text=True, timeout=600, env=scanner_env(),
        )
        if result.returncode != 0:
            return "error", [], result.stderr[-500:] or f"Trivy exited {result.returncode}"
        data = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return "error", [], str(exc)[:500]

    findings = []
    for section in data.get("Results", []):
        for vuln in section.get("Vulnerabilities") or []:
            package = vuln.get("PkgName") or "unknown package"
            version = vuln.get("InstalledVersion") or "unknown version"
            findings.append(Finding(
                id=f"CTR-{first_id + len(findings):03d}", type="container",
                title=f"{vuln.get('VulnerabilityID', 'Unknown vulnerability')} in image package {package}",
                component=f"{package}@{version}", dependency_path=[],
                severity=str(vuln.get("Severity") or "unknown").lower(),
                evidence={"tool": "trivy", "image": image_ref,
                          "target": section.get("Target"), "class": section.get("Class"),
                          "vulnerability_id": vuln.get("VulnerabilityID"),
                          "installed_version": version, "fixed_version": vuln.get("FixedVersion"),
                          "raw_output": str(output)},
                source_agent=AGENT,
                fix=(f"Upgrade to {vuln['FixedVersion']}." if vuln.get("FixedVersion") else None),
            ))
    return "completed", findings, None


def run(ctx: RunContext) -> None:
    recon = ctx.state["recon"]
    root = Path(recon["target_dir"])
    findings = []
    inspected = []

    def add(kind: str, title: str, component: str, severity: str,
            path: str, line: int, detail: str, fix: str) -> None:
        prefix = "CI" if kind == "ci_cd" else "CTR"
        count = sum(f.id.startswith(prefix + "-") for f in findings) + 1
        findings.append(Finding(
            id=f"{prefix}-{count:03d}", type=kind, title=title,
            component=component, dependency_path=[], severity=severity,
            evidence={"tool": "static inspection", "file": path, "line": line,
                      "observed": detail, "commit": recon.get("commit")},
            source_agent=AGENT, fix=fix,
        ))

    for rel in recon.get("dockerfiles", []):
        path = root / rel
        if not path.is_file():
            continue
        inspected.append(rel)
        instructions = list(_lines(path))
        from_lines = [(n, s) for n, s in instructions if re.match(r"^FROM\s+", s, re.I)]
        if not from_lines:
            continue
        for number, line in from_lines:
            image = line.split()[1]
            if image.lower() != "scratch" and (":" not in image.split("/")[-1] or image.endswith(":latest")) and "@sha256:" not in image:
                add("container", "Base image is not pinned to a stable version", image,
                    "medium", rel, number, line,
                    "Pin the base image to a reviewed version or digest.")
        last_from = from_lines[-1][0]
        users = [(number, line) for number, line in instructions
                 if number > last_from and re.match(r"^USER\s+", line, re.I)]
        if not users:
            add("container", "Final container stage has no USER instruction", rel,
                "medium", rel, last_from, from_lines[-1][1],
                "Set an explicit non-root USER in the final image stage.")
        elif users[-1][1].split()[1].lower() in {"root", "0"}:
            add("container", "Final container stage runs as root", rel,
                "medium", rel, users[-1][0], users[-1][1],
                "Use a dedicated non-root user in the final image stage.")

    for rel in recon.get("compose_files", []):
        path = root / rel
        if not path.is_file():
            continue
        inspected.append(rel)
        for number, line in _lines(path):
            match = re.match(r"^image:\s*['\"]?([^\s'\"#]+)", line)
            if match:
                image = match.group(1)
                if image.endswith(":latest") or (":" not in image.split("/")[-1] and "@sha256:" not in image):
                    add("container", "Compose image uses a moving tag", image,
                        "medium", rel, number, line,
                        "Pin the image to a reviewed version or digest.")

    for rel in recon.get("ci_workflows", []):
        path = root / rel
        if not path.is_file():
            continue
        inspected.append(rel)
        for number, line in _lines(path):
            match = re.match(r"^-?\s*uses:\s*['\"]?([^\s'\"#]+)", line)
            if not match:
                continue
            action = match.group(1)
            if action.startswith("./") or action.startswith("docker://"):
                continue
            if not PINNED_ACTION.fullmatch(action):
                add("ci_cd", "GitHub Action is not pinned to a commit", action,
                    "medium", rel, number, line,
                    "Pin the action reference to a reviewed 40-character commit SHA.")

    image_ref = os.environ.get("GUARDIAN_IMAGE_REF", "").strip()
    image_status = "not_requested"
    image_error = None
    if image_ref:
        image_status, image_findings, image_error = _scan_image(
            ctx, image_ref, 1 + sum(f.id.startswith("CTR-") for f in findings)
        )
        findings.extend(image_findings)
        if image_error:
            ctx.note(AGENT, f"image scan {image_status}: {image_error}")

    for finding in findings:
        ctx.add_finding(finding)
    status = "completed" if inspected or image_status == "completed" else "not_applicable"
    ctx.state["container_ci"] = {
        "status": status,
        "method": "static_file_inspection_and_trivy_image" if image_status == "completed" else "static_file_inspection",
        "inspected_files": inspected, "finding_count": len(findings),
        "image_ref": image_ref or None,
        "image_scan_status": image_status,
        "image_scan_performed": image_status == "completed",
        "image_scan_error": image_error,
    }
    ctx.save("container_ci.json", ctx.state["container_ci"])
    ctx.note(AGENT, f"inspected {len(inspected)} file(s), emitted {len(findings)} finding(s)")
