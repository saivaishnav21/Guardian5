"""
Report Generator  –  guardian/report.py
========================================
Person 5 contribution.

Produces two artefacts per run:
  • report.md   – concise human-readable Markdown summary
  • report.json – complete machine-readable findings and evidence

Data sources (read from RunContext.state):
  - ctx.state["recon"]               – repo metadata
  - ctx.state["graph"]               – SBOM summary
  - ctx.state["findings"]            – raw findings list (may be absent)
  - ctx.state["processed_findings"]  – enriched findings from Evidence & Risk Agent

Usage (called by orchestrator or Streamlit app):
    from guardian.report import generate
    md_path, json_path = generate(ctx)
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from guardian.agents.base import RunContext

# ---------------------------------------------------------------------------
# Risk-level ordering for sorting / display
# ---------------------------------------------------------------------------
_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unrated": 4}
_OVERVIEW_LIMIT = 20
_DETAIL_LIMIT = 5
_RISK_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "unrated":  "⚪",
}
_SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "unknown":  "⚪",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _risk_emoji(level: str) -> str:
    return _RISK_EMOJI.get(level.lower(), "⚪")


def _sev_emoji(sev: str) -> str:
    return _SEV_EMOJI.get(sev.lower(), "⚪")


def _dep_path_str(path: list) -> str:
    if not path:
        return "*(not available)*"
    return " → ".join(str(p) for p in path)


def _evidence_summary(evidence: dict | None) -> str:
    if not evidence:
        return "*(no evidence recorded)*"
    lines = []
    for k, v in evidence.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v, default=str)
        value = " ".join(str(v).split())
        if len(value) > 240:
            value = value[:237] + "..."
        lines.append(f"  - **{k}**: {value}")
    return "\n".join(lines)


def _cell(value: object) -> str:
    return " ".join(str(value).split()).replace("|", "\\|").replace("`", "\\`")


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            _RISK_ORDER.get(f.get("review_priority", f.get("risk_level", "unrated")), 99),
            f.get("id", ""),
        ),
    )


# ---------------------------------------------------------------------------
# Markdown builder
# ---------------------------------------------------------------------------

def _build_markdown(ctx: RunContext, findings: list[dict], summary: dict) -> str:
    now    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    recon  = ctx.state.get("recon", {})
    graph  = ctx.state.get("graph", {})
    g_sum  = graph.get("summary", {})
    ranked = _sorted_findings(findings)

    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        "# 🛡️ Guardian AI – Supply Chain Security Report",
        "",
        f"**Generated:** {now}",
        f"**Repository:** {ctx.repo_url}",
    ]
    if recon.get("commit"):
        lines.append(f"**Commit:** `{recon['commit']}`")
    lines.append("")

    # ── Executive Summary ───────────────────────────────────────────────────
    lines += [
        "---",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total components scanned | {g_sum.get('total_components', 'n/a')} |",
        f"| Direct dependencies | {g_sum.get('direct', 'n/a')} |",
        f"| Transitive dependencies | {g_sum.get('transitive', 'n/a')} |",
        f"| Ecosystems | {', '.join(recon.get('ecosystems', [])) or 'n/a'} |",
        f"| Total findings | {summary.get('total_findings', 0)} |",
        f"| Critical | {summary['risk_counts'].get('critical', 0)} |",
        f"| High | {summary['risk_counts'].get('high', 0)} |",
        f"| Medium | {summary['risk_counts'].get('medium', 0)} |",
        f"| Low | {summary['risk_counts'].get('low', 0)} |",
        f"| Unrated | {summary['risk_counts'].get('unrated', 0)} |",
        "",
        "Finding counts are observations from scanners and may include the same issue in multiple scans.",
        "",
    ]

    if summary.get("type_counts"):
        lines.append("**By type:** " + ", ".join(
            f"{_cell(kind)}: {count}" for kind, count in sorted(summary["type_counts"].items())
        ))
        lines.append("")

    lines += ["## Scan Coverage", ""]
    for label, state_key in (("Vulnerability matching", "vulnerability"),
                             ("Container and CI inspection", "container_ci"),
                             ("Suspicious static checks", "suspicious")):
        status = ctx.state.get(state_key, {}).get("status", "not_run")
        lines.append(f"- **{label}:** {status}")
    lines.append(f"- **Demo branch comparison:** {ctx.state.get('suspicious', {}).get('branch_comparison', 'not_run')}")
    lines.append(f"- **Local image scan:** {ctx.state.get('container_ci', {}).get('image_scan_status', 'not_run')}")
    lines += ["- **Validation:** not performed in Day 1", ""]

    # ── Findings table ───────────────────────────────────────────────────────
    if findings:
        lines += [
            "---",
            f"## Priority Findings (top {min(len(findings), _OVERVIEW_LIMIT)} of {len(findings)})",
            "",
            "| ID | Type | Component | Severity | Scanner risk | Review priority | Title |",
            "|----|------|-----------|----------|--------------|-----------------|-------|",
        ]
        for f in ranked[:_OVERVIEW_LIMIT]:
            rid   = f.get("id", "?")
            ftype = f.get("type", "?")
            comp  = f.get("component", "?")
            sev   = f.get("severity", "unknown")
            risk  = f.get("risk_level", "unrated")
            title = f.get("title", "")[:60]
            lines.append(
                f"| {_cell(rid)} | {_cell(ftype)} | {_cell(comp)} | "
                f"{_sev_emoji(sev)} {_cell(sev)} | "
                f"{_risk_emoji(risk)} {_cell(risk)} | "
                f"{_cell(f.get('review_priority', risk))} | {_cell(title)} |"
            )
        lines += ["", "All findings and full evidence are in [report.json](report.json).", ""]

        lines += ["## Example from each detector", "",
                  "| Type | ID | Risk | Finding |",
                  "|------|----|------|---------|"]
        for kind in sorted(summary.get("type_counts", {})):
            example = next((item for item in ranked if item.get("type") == kind), None)
            if example:
                lines.append(
                    f"| {_cell(kind)} | {_cell(example.get('id', '?'))} | "
                    f"{_cell(example.get('risk_level', 'unrated'))} | "
                    f"{_cell(example.get('title', ''))} |"
                )
        lines.append("")
    else:
        lines += [
            "---",
            "## Findings",
            "",
            "> No findings were produced by the completed detection stages. Check scan coverage above.",
            "",
        ]

    # ── Detailed findings ────────────────────────────────────────────────────
    if findings:
        lines += ["---", f"## Evidence for the top {min(len(findings), _DETAIL_LIMIT)} findings", ""]
        for f in ranked[:_DETAIL_LIMIT]:
            rid   = f.get("id", "?")
            risk  = f.get("risk_level", "unrated")
            sev   = f.get("severity", "unknown")
            emoji = _risk_emoji(risk)

            lines += [
                f"### {emoji} {_cell(rid)} – {_cell(f.get('title', ''))}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Type** | {f.get('type', '?')} |",
                f"| **Component** | {_cell(f.get('component', '?'))} |",
                f"| **Severity** | {_sev_emoji(sev)} {sev} |",
                f"| **Risk Level** | {emoji} {risk} |",
                f"| **Source Agent** | {f.get('source_agent', '?')} |",
                "",
            ]

            # Risk rationale
            if f.get("risk_rationale"):
                lines += [
                    "**Risk Rationale:**",
                    f"> {f['risk_rationale']}",
                    "",
                ]

            # Dependency path
            lines += [
                "**Dependency Path:**",
                f"> {_dep_path_str(f.get('dependency_path', []))}",
                "",
            ]

            # Evidence
            ev = f.get("evidence") or {}
            lines += [
                "**Evidence:**",
                _evidence_summary(ev),
                "",
            ]

            # Remediation
            if f.get("remediation"):
                lines += [
                    "**Remediation:**",
                    f"> {f['remediation']}",
                    "",
                ]

            risk_ai = f.get("ai_assessment") or {}
            suspicious_ai = f.get("ai_suspicious") or {}
            if risk_ai.get("status") == "completed" or suspicious_ai.get("status") == "completed":
                lines += ["**🤖 AI Advisory — not verified:**", ""]
                if risk_ai.get("status") == "completed":
                    lines += [
                        f"- Suggested review priority: {_cell(risk_ai['priority'])}; {_cell(risk_ai['reason'])}",
                        f"- Evidence references: {_cell(', '.join(risk_ai['evidence_refs']))}; "
                        f"unknown: {_cell(', '.join(risk_ai['unknowns']) or 'none listed')}",
                    ]
                if suspicious_ai.get("status") == "completed":
                    lines += [
                        f"- Hypothesis: {_cell(suspicious_ai['hypothesis'])}",
                        f"- Check next: {_cell(suspicious_ai['check_next'])}; "
                        f"evidence references: {_cell(', '.join(suspicious_ai['evidence_refs']))}",
                    ]
                lines.append("")

            # Notes from other agents
            notes = f.get("notes", [])
            if notes:
                lines += ["**Notes:**"]
                for note in notes:
                    lines.append(f"- {note}")
                lines.append("")

            lines.append("---")
            lines.append("")

    # ── Responsible AI notice ────────────────────────────────────────────────
    lines += [
        "## Responsible AI Notice",
        "",
        "Risk levels in this report follow reported severity **deterministically**.",
        "Evidence source quality is noted in the rationale; AI does not set scanner risk.",
        "AI assessments are unverified advice. They may raise review order but never change scanner risk.",
        "New CVE IDs and versions are rejected; review all other claims manually.",
        "",
        "---",
        "*Guardian AI · Software Supply Chain Guardian · Hackathon Day 1*",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON builder
# ---------------------------------------------------------------------------

def _build_json(ctx: RunContext, findings: list[dict], summary: dict) -> dict:
    recon = ctx.state.get("recon", {})
    graph = ctx.state.get("graph", {})
    inventory = []
    graph_path = graph.get("graph_json")
    if graph_path and Path(graph_path).is_file():
        graph_data = json.loads(Path(graph_path).read_text(encoding="utf-8"))
        inventory = [
            {"id": n.get("id"), "name": n.get("name"), "version": n.get("version"),
             "scope": n.get("scope"), "direct": n.get("direct"), "depth": n.get("depth")}
            for n in graph_data.get("nodes", []) if n.get("kind") == "component"
        ]

    return {
        "guardian_report": {
            "schema_version": "1.0",
            "generated_at":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "repo_url":       ctx.repo_url,
            "commit":         recon.get("commit"),
            "run_dir":        str(ctx.run_dir),
        },
        "summary": summary,
        "graph_summary": graph.get("summary", {}),
        "inventory": inventory,
        "artifacts": {"sbom": graph.get("sbom_path"), "graph_json": graph_path,
                      "graph_html": graph.get("graph_html")},
        "scan_status": {
            "vulnerability": ctx.state.get("vulnerability", {}).get("status", "not_run"),
            "container_ci": ctx.state.get("container_ci", {}).get("status", "not_run"),
            "container_image": ctx.state.get("container_ci", {}).get("image_scan_status", "not_run"),
            "suspicious": ctx.state.get("suspicious", {}).get("status", "not_run"),
            "branch_comparison": ctx.state.get("suspicious", {}).get("branch_comparison", "not_run"),
        },
        "validation": {"status": "not_performed_day_1"},
        "ecosystems": recon.get("ecosystems", []),
        "findings": _sorted_findings(findings),
        "skipped_findings": ctx.state.get("skipped_findings", []),
        "responsible_ai": {
            "risk_assignment": "deterministic",
            "ai_role":         "unverified risk and suspicious-change advisory",
            "hallucination_guards": [
                "AI output checked for new CVE IDs, versions, and evidence references",
                "AI never modifies risk_level or evidence fields",
                "Deterministic fallback when API key absent",
            ],
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(ctx: RunContext) -> tuple[Path, Path]:
    """
    Generate Markdown and JSON reports.

    Returns
    -------
    (md_path, json_path)  –  both are Path objects pointing to files in ctx.run_dir.
    """
    # Prefer processed findings (enriched by Evidence & Risk Agent)
    findings: list[dict] = ctx.state.get("processed_findings", ctx.state.get("findings", []))

    # Pull summary from evidence_risk output if available
    er_state = {}
    er_path  = ctx.run_dir / "evidence_risk.json"
    if er_path.exists():
        try:
            er_state = json.loads(er_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            er_state = {}

    er_summary = er_state.get("summary", {})

    risk_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for f in findings:
        rl = f.get("risk_level", "unrated")
        risk_counts[rl] = risk_counts.get(rl, 0) + 1
        kind = f.get("type", "unknown")
        type_counts[kind] = type_counts.get(kind, 0) + 1

    summary: dict[str, Any] = {
        "total_findings":        len(findings),
        "total_input_findings":  er_summary.get("total_input", len(findings)),
        "total_skipped":         er_summary.get("total_skipped", 0),
        "risk_counts":           risk_counts,
        "type_counts":           type_counts,
        "ai_risk_reviews_used": sum(f.get("ai_assessment", {}).get("status") == "completed" for f in findings),
        "ai_suspicious_reviews_used": sum(f.get("ai_suspicious", {}).get("status") == "completed" for f in findings),
    }

    md_text   = _build_markdown(ctx, findings, summary)
    json_data = _build_json(ctx, findings, summary)

    md_path = ctx.run_dir / "report.md"
    md_path.write_text(md_text, encoding="utf-8")
    json_path = ctx.save("report.json", json_data)

    ctx.note("Report Generator", f"Markdown -> {md_path}")
    ctx.note("Report Generator", f"JSON     -> {json_path}")

    return md_path, json_path
