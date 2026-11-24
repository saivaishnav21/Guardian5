import re
import shutil
import subprocess

from guardian.agents.base import RunContext
from guardian.agents.groq_recon import suggest_manifests
from guardian.secrets import scanner_env

AGENT = "Recon Agent"

# Only public GitHub repos are accepted (sandbox rule: no outside infrastructure).
# A /tree/<ref> suffix selects one branch or tag so a fix branch can be rescanned.
URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?"
    r"(?:/tree/(?P<ref>[\w./-]+?))?/?$"
)
SKIP_DIRS = {".git", "node_modules"}

ECOSYSTEM_FILES = {
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "pom.xml": "maven", "build.gradle": "gradle",
    "requirements.txt": "pypi", "poetry.lock": "pypi", "Pipfile.lock": "pypi",
    "go.mod": "go",
}
NPM_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
PRIORITY_MANIFEST_SUFFIXES = {
    ".json", ".yaml", ".yml", ".toml", ".xml", ".lock", ".gradle", ".mod", ".sum", ".txt",
    ".kts", ".sbt", ".csproj", ".fsproj", ".gemspec", ".podspec",
}
MAX_GROQ_CANDIDATES = 200


def parse_repo_url(url: str) -> tuple[str, str | None]:
    """Split an accepted GitHub URL into a clone URL and an optional branch/tag."""
    match = URL_RE.match(str(url).strip())
    if not match:
        raise ValueError(
            "Only public https://github.com/<owner>/<repo> URLs are allowed, "
            "optionally with /tree/<branch>."
        )
    ref = match.group("ref")
    if ref and (".." in ref or ref.startswith("/") or ref.endswith("/")):
        raise ValueError("Branch or tag name is not valid.")
    clone_url = f"https://github.com/{match.group('owner')}/{match.group('repo')}.git"
    return clone_url, ref


def run(ctx: RunContext) -> None:
    url = ctx.repo_url
    clone_url, ref = parse_repo_url(url)

    dest = ctx.run_dir / "target"
    ctx.note(AGENT, f"cloning {clone_url} (shallow, ref={ref or 'default branch'})")
    clone_cmd = ["git", "clone", "--depth", "1"]
    if ref:
        clone_cmd += ["--branch", ref]
    clone_cmd += [clone_url, str(dest)]
    subprocess.run(clone_cmd, check=True, env=scanner_env())
    commit = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, env=scanner_env(),
    ).stdout.strip()
    checked_out = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, check=False, env=scanner_env(),
    ).stdout.strip() or "HEAD"

    found = {"manifests": [], "dockerfiles": [], "compose_files": [], "ci_workflows": []}
    ecosystems = set()
    unknown_candidates = []

    for p in dest.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(dest)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        name = p.name
        if name in ECOSYSTEM_FILES:
            found["manifests"].append(str(rel))
            ecosystems.add(ECOSYSTEM_FILES[name])
        elif p.suffix.lower() in PRIORITY_MANIFEST_SUFFIXES or not p.suffix:
            unknown_candidates.append(rel.as_posix())
        if name.lower().startswith("dockerfile") or name.lower().endswith(".dockerfile"):
            found["dockerfiles"].append(str(rel))
        if name in COMPOSE_NAMES:
            found["compose_files"].append(str(rel))
        if (len(rel.parts) >= 3 and rel.parts[0] == ".github" and rel.parts[1] == "workflows"
                and p.suffix in {".yml", ".yaml"}):
            found["ci_workflows"].append(str(rel))

    actions = []
    # npm project without a lockfile: resolve one WITHOUT installing or running scripts
    has_lock = any((dest / lf).exists() for lf in NPM_LOCKFILES)
    if (dest / "package.json").exists() and not has_lock:
        npm = shutil.which("npm")
        if not npm:
            raise RuntimeError("npm not found. Install Node.js and npm first.")
        ctx.note(AGENT, "no lockfile found, generating one (lockfile-only, scripts disabled)")
        subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts"],
                       cwd=dest, check=True, env=scanner_env())
        actions.append("generated package-lock.json via npm --package-lock-only --ignore-scripts")

    unknown_candidates.sort(key=lambda path: (path.count("/"), path))
    ai_recon = suggest_manifests(unknown_candidates[:MAX_GROQ_CANDIDATES])
    ai_recon["candidate_count"] = len(unknown_candidates)
    ai_recon["submitted_count"] = min(len(unknown_candidates), MAX_GROQ_CANDIDATES)
    if ai_recon["status"] == "error":
        ctx.note(AGENT, f"Groq suggestions unavailable ({ai_recon['error_type']}); continuing")

    recon = {
        "repo_url": url,
        "clone_url": clone_url,
        "requested_ref": ref,
        "checked_out_ref": checked_out,
        "commit": commit,
        "target_dir": str(dest),
        "ecosystems": sorted(ecosystems),
        "ai_recon": ai_recon,
        **found,
        "actions_taken": actions,
    }
    ctx.state["recon"] = recon
    ctx.save("recon.json", recon)
    ctx.note(AGENT, f"ref {checked_out} @ {commit[:8]}, ecosystems={sorted(ecosystems)}, "
                    f"dockerfiles={len(found['dockerfiles'])}, workflows={len(found['ci_workflows'])}")
