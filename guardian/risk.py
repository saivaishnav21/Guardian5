"""Contextual risk ranking (Day 2, Person 1).

Deterministic: the same inputs always give the same ranking. No LLM is used here.
Only facts we can observe change the score; things we cannot measure go to `unknowns`.

Usage:  python -m guardian.risk runs/<timestamp>
"""
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---- Tunable weights (documented in the output so a reviewer can audit them) ----
SEVERITY_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "unknown": 30}
SEVERITY_ORDER = ["unknown", "low", "medium", "high", "critical"]
SEVERITY_ALIASES = {
    "moderate": "medium", "negligible": "low", "informational": "low",
    "info": "low", "important": "high",
}
W_RUNTIME_SCOPE = 5      # SBOM says the component is required at runtime
W_OPTIONAL_SCOPE = -15   # SBOM says optional/excluded (for example dev-only)
W_IN_IMAGE = 10          # seen by an image scan (Trivy)
W_FIX_AVAILABLE = 0      # a fixed version is recorded, so it is actionable
W_TWO_SCANNERS = 5       # confirmed by two different scanners
LEVELS = [(80, "critical"), (60, "high"), (35, "medium"), (0, "low")]

ADVISORY_RE = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})", re.I)

SOURCE_FILE = {
    "vulnerability": "vulnerability.json",
    "suspicious_change": "suspicious.json",
    "container": "container_ci.json",
    "ci_cd": "container_ci.json",
}

ALWAYS_UNKNOWN = [
    "reachability not measured (is the vulnerable code actually called?)",
    "exposure not measured (is it reachable from outside?)",
    "known-exploitation status not checked",
]


# ------------------------------------------------------------------ loading
def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def extract_findings(obj) -> list:
    """Accept a list of findings, or a dict that holds one under a common key."""
    if isinstance(obj, list):
        return [f for f in obj if isinstance(f, dict)]
    if isinstance(obj, dict):
        for key in ("findings", "items", "results"):
            if isinstance(obj.get(key), list):
                return [f for f in obj[key] if isinstance(f, dict)]
    return []


def load_run(run_dir):
    """Return (findings, graph, source_description) from a runs/<timestamp>/ folder."""
    run = Path(run_dir)
    findings, source = [], "none"

    state_file = run / "state.json"
    if state_file.exists():
        state = load_json(state_file)
        findings = extract_findings(state.get("state", {})) if isinstance(state, dict) else []
        if findings:
            source = "state.json"

    if not findings and (run / "report.json").exists():
        findings = extract_findings(load_json(run / "report.json"))
        if findings:
            source = "report.json"

    if not findings:
        for name in ("vulnerability.json", "suspicious.json", "container_ci.json"):
            if (run / name).exists():
                findings += extract_findings(load_json(run / name))
        if findings:
            source = "vulnerability.json + suspicious.json + container_ci.json"

    graph = load_json(run / "graph.json") if (run / "graph.json").exists() else {}
    return findings, graph, source


# ------------------------------------------------------------------ helpers
def normalize_severity(value) -> str:
    s = str(value or "unknown").strip().lower()
    s = SEVERITY_ALIASES.get(s, s)
    return s if s in SEVERITY_BASE else "unknown"


def finding_severity(f: dict) -> str:
    """Top-level severity, or the one stored inside the scanner evidence."""
    sev = normalize_severity(f.get("severity"))
    if sev == "unknown":
        ev = f.get("evidence")
        if isinstance(ev, dict):
            sev = normalize_severity(ev.get("severity"))
    return sev


def finding_fix(f: dict):
    """A recorded fix, from the finding or from the scanner evidence."""
    if f.get("fix"):
        return f["fix"]
    ev = f.get("evidence")
    if isinstance(ev, dict):
        for k in ("fix", "fixed_in", "fix_versions", "fixed_versions", "fixed_version"):
            if ev.get(k):
                return ev[k]
    return None


def level_for(score: float) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "low"


def build_graph_index(graph: dict):
    """Map 'name@version', scoped names and purls to graph nodes."""
    by_component, by_id = {}, {}
    for n in graph.get("nodes", []):
        by_id[n.get("id")] = n
        keys = set()
        name, ver, group = n.get("name"), n.get("version"), n.get("group")
        if name and ver:
            keys.add(f"{name}@{ver}")
            if group:
                keys.add(f"{group}/{name}@{ver}")
        if n.get("purl"):
            keys.add(n["purl"])
        if n.get("id"):
            keys.add(n["id"])
        for k in keys:
            by_component.setdefault(k, n)
    return by_component, by_id


def _pick(ids):
    ids = {i.upper() for i in ids}
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    if cves:
        return cves[0]
    return sorted(ids)[0] if ids else None


def advisory_id(f: dict):
    """The CVE/GHSA this finding is about (title first, then scanner evidence)."""
    found = _pick(ADVISORY_RE.findall(str(f.get("title", ""))))
    if found:
        return found
    ev = f.get("evidence")
    if f.get("type") == "vulnerability" and isinstance(ev, dict):
        found = _pick(ADVISORY_RE.findall(
            json.dumps([ev.get("cve_ids"), ev.get("vulnerability_id")], default=str)))
        if found:
            return found
        return _pick(ADVISORY_RE.findall(json.dumps(ev, default=str)[:4000]))
    return None


def detect_scanners(f: dict) -> set:
    blob = (str(f.get("source_agent", "")) + " "
            + json.dumps(f.get("evidence"), default=str)[:3000]).lower()
    found = set()
    if "grype" in blob:
        found.add("grype")
    if "trivy" in blob:
        found.add("trivy")
    return found


def group_key(f: dict) -> str:
    adv = advisory_id(f)
    title = re.sub(r"\s+", " ", str(f.get("title", "")).strip().lower())
    return f"{f.get('type', 'unknown')}:{adv or title}:{f.get('component', '')}"


def worst_severity(severities) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.index(s))


# ------------------------------------------------------------------ scoring
def score_item(severity, ftype, node, scanners, fix):
    breakdown = [{"factor": "scanner_severity", "points": SEVERITY_BASE[severity],
                  "why": f"scanner severity is '{severity}'"}]
    unknowns = list(ALWAYS_UNKNOWN)
    is_package_finding = ftype in ("vulnerability", "suspicious_change")

    if is_package_finding:
        if node is None:
            unknowns.append("component not found in graph.json, so ownership and scope are unknown")
        else:
            scope = node.get("scope")
            if scope == "required":
                breakdown.append({"factor": "runtime_scope", "points": W_RUNTIME_SCOPE,
                                  "why": "SBOM marks the component as required at runtime"})
            elif scope in ("optional", "excluded"):
                breakdown.append({"factor": "optional_scope", "points": W_OPTIONAL_SCOPE,
                                  "why": f"SBOM scope is '{scope}' (likely not shipped at runtime)"})
            else:
                unknowns.append("runtime versus dev scope not recorded in the SBOM")

    if "trivy" in scanners:
        breakdown.append({"factor": "seen_in_image_scan", "points": W_IN_IMAGE,
                          "why": "reported by the built-image scan"})
    if len(scanners) >= 2:
        breakdown.append({"factor": "two_scanners_agree", "points": W_TWO_SCANNERS,
                          "why": "confirmed by more than one scanner"})
    if ftype == "vulnerability":
        if fix:
            breakdown.append({"factor": "fix_available", "points": W_FIX_AVAILABLE,
                              "why": "a fixed version is recorded by the scanner"})
        else:
            unknowns.append("no fixed version recorded")

    total = max(0, min(100, sum(b["points"] for b in breakdown)))
    return total, breakdown, unknowns


def rationale_text(breakdown, score, level):
    parts = [f"{b['points']:+d} {b['why']}" if i else f"base {b['points']}: {b['why']}"
             for i, b in enumerate(breakdown)]
    return "; ".join(parts) + f" => {score} ({level})"


# ------------------------------------------------------------------ main logic
def assess(findings: list, graph: dict, meta: dict | None = None) -> dict:
    by_component, by_id = build_graph_index(graph or {})

    # Group findings that describe the same issue (same advisory on the same component).
    # Findings with no advisory ID stay separate (numbered in a stable order).
    groups, seen_plain = {}, {}
    for f in sorted(findings, key=lambda x: str(x.get("id"))):
        key = group_key(f)
        if advisory_id(f) is None:
            n = seen_plain.get(key, 0) + 1
            seen_plain[key] = n
            key = f"{key}#{n}"
        groups.setdefault(key, []).append(f)

    items = []
    for key, members in groups.items():
        first = members[0]
        ftype = first.get("type", "unknown")
        severity = worst_severity([finding_severity(m) for m in members])
        scanners = set()
        for m in members:
            scanners |= detect_scanners(m)
        fix = next((finding_fix(m) for m in members if finding_fix(m)), None)

        node = None
        ev = first.get("evidence")
        for cand in (first.get("component"), ev.get("purl") if isinstance(ev, dict) else None):
            if cand and cand in by_component:
                node = by_component[cand]
                break

        score, breakdown, unknowns = score_item(severity, ftype, node, scanners, fix)
        level = level_for(score)

        if node:
            path_ids = node.get("path") or []
            path_readable = []
            for p in path_ids:
                pn = by_id.get(p)
                if pn is None:
                    path_readable.append(str(p))
                elif pn.get("version"):
                    path_readable.append(f"{pn.get('name')}@{pn.get('version')}")
                else:
                    path_readable.append(str(pn.get("name")))
            ownership = {
                "direct": node.get("direct"),
                "depth": node.get("depth"),
                "introduced_by": (by_id.get(node.get("introduced_by")) or {}).get("name") or node.get("introduced_by"),
                "dependency_path": path_readable,
            }
        else:
            ownership = {"direct": None, "depth": None, "introduced_by": None,
                         "dependency_path": first.get("dependency_path") or []}

        refs = [f"finding:{m.get('id')}" for m in members]
        if ftype in SOURCE_FILE:
            refs.append(SOURCE_FILE[ftype])
        if node:
            refs.append(f"graph.json:{node.get('id')}")

        items.append({
            "key": key,
            "title": first.get("title"),
            "type": ftype,
            "component": first.get("component"),
            "severity": severity,
            "risk_score": score,
            "risk_level": level,
            "ownership": ownership,
            "scanners": sorted(scanners),
            "fix": fix,
            "score_breakdown": breakdown,
            "evidence_refs": refs,
            "finding_ids": sorted(str(m.get("id")) for m in members),
            "unknowns": unknowns,
            "rationale": rationale_text(breakdown, score, level),
        })

    # Deterministic order: score high to low, direct dependencies first, then key.
    items.sort(key=lambda i: (-i["risk_score"], 0 if i["ownership"]["direct"] else 1, i["ownership"]["depth"] if i["ownership"]["depth"] is not None else 99, i["key"]))
    for rank, item in enumerate(items, start=1):
        item["rank"] = rank

    by_level = {}
    for it in items:
        by_level[it["risk_level"]] = by_level.get(it["risk_level"], 0) + 1

    fingerprint = hashlib.sha256(
        json.dumps([[i["key"], i["risk_score"]] for i in items]).encode("utf-8")
    ).hexdigest()

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ranking_fingerprint": fingerprint,
        "method": {
            "llm_used": False,
            "weights": {
                "severity_base": SEVERITY_BASE,
                "runtime_scope": W_RUNTIME_SCOPE,
                "optional_scope": W_OPTIONAL_SCOPE,
                "seen_in_image_scan": W_IN_IMAGE,
                "fix_available": W_FIX_AVAILABLE,
                "two_scanners_agree": W_TWO_SCANNERS,
            },
            "level_thresholds": LEVELS,
            "note": "Reachability, exposure and exploitation are not measured, so they are listed as unknowns and do not change the score.",
        },
        "meta": meta or {},
        "summary": {
            "input_findings": len(findings),
            "ranked_items": len(items),
            "by_level": by_level,
        },
        "items": items,
    }


def write_assessment(result: dict, out_path) -> str:
    Path(out_path).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return str(out_path)


def assess_run_dir(run_dir) -> dict:
    findings, graph, source = load_run(run_dir)
    return assess(findings, graph, meta={"run_dir": str(run_dir), "findings_loaded_from": source})


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: python -m guardian.risk runs/<timestamp>")
    run_dir = Path(sys.argv[1])
    result = assess_run_dir(run_dir)
    out = write_assessment(result, run_dir / "risk_assessment.json")
    s = result["summary"]
    print(f"Wrote {out}")
    print(f"{s['input_findings']} findings -> {s['ranked_items']} ranked items {s['by_level']}")
    print("fingerprint:", result["ranking_fingerprint"])
    for it in result["items"][:10]:
        print(f"  #{it['rank']:>2} {it['risk_score']:>3} {it['risk_level']:<8} {it['component']}  {it['title']}")
