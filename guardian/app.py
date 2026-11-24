"""
Guardian AI – Streamlit Dashboard  (guardian/app.py)
=====================================================
Person 5 contribution.

Provides a professional web UI for running the Guardian AI pipeline and
viewing scan results.  It delegates to the existing orchestrator rather
than re-implementing detection logic.

Run:
    streamlit run guardian/app.py

Environment variable (optional):
    GROQ_API_KEY=<key>   – enables AI prose explanations in the Evidence
                                & Risk Agent.  The dashboard never displays the
                                key; it is read exclusively from the environment.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import traceback
from pathlib import Path
from guardian.secrets import groq_key

import streamlit as st

# ── Page config must be first Streamlit call ─────────────────────────────────
st.set_page_config(
    page_title="Guardian AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .guardian-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        text-align: center;
        color: white;
    }
    .guardian-header h1 { font-size: 2.4rem; margin: 0; }
    .guardian-header p  { opacity: .75; margin-top: .4rem; }

    .metric-card {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 1rem 1.5rem;
        border-left: 4px solid #0f3460;
        margin-bottom: .75rem;
    }
    .risk-critical { border-left-color: #dc3545 !important; }
    .risk-high     { border-left-color: #fd7e14 !important; }
    .risk-medium   { border-left-color: #ffc107 !important; }
    .risk-low      { border-left-color: #28a745 !important; }
    .risk-unrated  { border-left-color: #adb5bd !important; }

    .finding-card {
        background: white;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1.2rem;
        margin-bottom: 1rem;
        box-shadow: 0 1px 3px rgba(0,0,0,.08);
    }
    .badge {
        display: inline-block;
        padding: .25em .6em;
        border-radius: .35rem;
        font-size: .78rem;
        font-weight: 600;
        color: white;
    }
    .badge-critical { background: #dc3545; }
    .badge-high     { background: #fd7e14; }
    .badge-medium   { background: #ffc107; color: #212529; }
    .badge-low      { background: #28a745; }
    .badge-unrated  { background: #adb5bd; color: #212529; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_RISK_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "unrated": "⚪",
}
_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unrated": 4}

_SAMPLE_REPOS = [
    "https://github.com/OWASP/NodeGoat.git",
    "https://github.com/juice-shop/juice-shop.git",
    "https://github.com/expressjs/express.git",
]

# ---------------------------------------------------------------------------
# Session-state helpers
# ---------------------------------------------------------------------------

def _init_state() -> None:
    for key, default in {
        "ctx":        None,
        "md_path":    None,
        "json_path":  None,
        "run_error":  None,
        "last_repo":  "",
    }.items():
        if key not in st.session_state:
            st.session_state[key] = default


# ---------------------------------------------------------------------------
# Pipeline runner (called inside st.spinner)
# ---------------------------------------------------------------------------

def _run_pipeline(repo_url: str) -> None:
    """Execute the full Guardian pipeline, updating session state."""
    st.session_state.ctx       = None
    st.session_state.md_path   = None
    st.session_state.json_path = None
    st.session_state.run_error = None
    st.session_state.last_repo = repo_url

    try:
        # Import here so errors surface clearly
        from guardian.orchestrator import run_pipeline  # type: ignore[import]
        ctx = run_pipeline(repo_url)
        report = ctx.state["report"]

        st.session_state.ctx       = ctx
        st.session_state.md_path   = report["markdown"]
        st.session_state.json_path = report["json"]

    except Exception as exc:  # noqa: BLE001
        st.session_state.run_error = {
            "message": str(exc),
            "traceback": traceback.format_exc(),
        }


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _sidebar() -> str | None:
    """Render sidebar. Returns repo URL to scan or None."""
    with st.sidebar:
        st.image(
            "https://img.icons8.com/color/96/shield.png",
            width=64,
        )
        st.title("Guardian AI")
        st.caption("Software Supply Chain Guardian")
        st.divider()

        st.subheader("🔍 Scan a Repository")
        repo_url = st.text_input(
            "Public GitHub URL",
            value=st.session_state.get("last_repo", _SAMPLE_REPOS[0]),
            placeholder="https://github.com/owner/repo.git",
        )

        st.caption("Quick picks:")
        for sample in _SAMPLE_REPOS:
            if st.button(sample.split("/")[-1].replace(".git", ""), key=f"btn_{sample}"):
                repo_url = sample

        if groq_key():
            st.success("🤖 AI explanations: **enabled**")
        else:
            st.info("🤖 AI explanations: **disabled**\n\nSet `GROQ_API_KEY` env var to enable.")

        st.divider()
        st.caption("Day 1 prototype")

        scan_clicked = st.button("🚀 Run Scan", type="primary", use_container_width=True)
        return repo_url if scan_clicked else None


# ---------------------------------------------------------------------------
# Results panels
# ---------------------------------------------------------------------------

def _render_summary(ctx) -> None:
    state = ctx.state
    recon = state.get("recon", {})
    graph = state.get("graph", {})
    g_sum = graph.get("summary", {})
    findings = state.get("processed_findings", state.get("findings", []))

    # Risk counts
    risk_counts: dict[str, int] = {}
    for f in findings:
        rl = f.get("risk_level", "unrated")
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    st.subheader("📊 Scan Summary")
    cols = st.columns(6)
    metrics = [
        ("Total Components", g_sum.get("total_components", "—")),
        ("Direct Deps",      g_sum.get("direct", "—")),
        ("Findings",         len(findings)),
        (f"🔴 Critical",     risk_counts.get("critical", 0)),
        (f"🟠 High",         risk_counts.get("high", 0)),
        (f"🟡 Medium",       risk_counts.get("medium", 0)),
    ]
    for col, (label, value) in zip(cols, metrics):
        col.metric(label, value)
    st.caption("Finding counts may overlap when different scanners report the same issue.")

    # Repo details
    with st.expander("ℹ️ Repository Details"):
        st.markdown(f"**URL:** {ctx.repo_url}")
        st.markdown(f"**Commit:** `{recon.get('commit', 'unknown')}`")
        st.markdown(f"**Ecosystems:** {', '.join(recon.get('ecosystems', [])) or 'none detected'}")
        st.markdown(f"**Manifests found:** {len(recon.get('manifests', []))}")
        st.markdown(f"**Dockerfiles:** {len(recon.get('dockerfiles', []))}")
        st.markdown(f"**CI Workflows:** {len(recon.get('ci_workflows', []))}")
        st.markdown(f"**Vulnerability scan:** {state.get('vulnerability', {}).get('status', 'not_run')}")
        st.markdown(f"**Container/CI inspection:** {state.get('container_ci', {}).get('status', 'not_run')}")
        st.markdown(f"**Local image scan:** {state.get('container_ci', {}).get('image_scan_status', 'not_run')}")
        st.markdown(f"**Branch comparison:** {state.get('suspicious', {}).get('branch_comparison', 'not_run')}")
        st.markdown(f"**Run directory:** `{ctx.run_dir}`")


def _render_findings(ctx) -> None:
    findings = ctx.state.get("processed_findings", ctx.state.get("findings", []))

    st.subheader(f"🔎 Findings ({len(findings)})")

    if not findings:
        st.info("No findings from completed detection stages.")
        st.info(
            "Check the report's scan coverage before interpreting an empty findings list."
        )
        return

    # Sort by risk
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _RISK_ORDER.get(f.get("risk_level", "unrated"), 99),
            f.get("id", ""),
        ),
    )

    # Filters
    col1, col2 = st.columns(2)
    with col1:
        risk_filter = st.multiselect(
            "Filter by Risk Level",
            options=["critical", "high", "medium", "low", "unrated"],
            default=[],
        )
    with col2:
        type_options = sorted({f.get("type", "?") for f in findings})
        type_filter = st.multiselect("Filter by Type", options=type_options, default=[])

    display = sorted_findings
    if risk_filter:
        display = [f for f in display if f.get("risk_level") in risk_filter]
    if type_filter:
        display = [f for f in display if f.get("type") in type_filter]

    if not display:
        st.info("No findings match these filters.")
        return

    page_size = 20
    page_count = (len(display) + page_size - 1) // page_size
    page = st.number_input("Page", min_value=1, max_value=page_count, value=1, step=1)
    start = (page - 1) * page_size
    st.caption(f"Showing {start + 1}–{min(start + page_size, len(display))} of {len(display)} matching findings")

    for f in display[start:start + page_size]:
        risk   = f.get("risk_level", "unrated")
        sev    = f.get("severity", "unknown")
        emoji  = _RISK_EMOJI.get(risk, "⚪")
        fid    = f.get("id", "?")
        title  = f.get("title", "")

        with st.expander(f"{emoji} `{fid}` – {title}  _(risk: **{risk}**)_"):
            c1, c2 = st.columns(2)
            c1.markdown(f"**Type:** {f.get('type', '?')}")
            c1.markdown(f"**Component:** `{f.get('component', '?')}`")
            c1.markdown(f"**Severity:** {sev}")
            c1.markdown(f"**Risk Level:** {emoji} **{risk}**")
            c2.markdown(f"**Source Agent:** {f.get('source_agent', '?')}")

            # Risk rationale
            if f.get("risk_rationale"):
                st.markdown("**Risk Rationale:**")
                st.info(f.get("risk_rationale"))

            # Dependency path
            dep_path = f.get("dependency_path", [])
            st.markdown("**Dependency Path:**")
            if dep_path:
                st.code(" → ".join(str(p) for p in dep_path))
            else:
                st.caption("*(not available for this finding)*")

            # Evidence
            evidence = f.get("evidence") or {}
            if evidence:
                st.markdown("**Evidence:**")
                st.json(evidence)

            # Remediation
            if f.get("remediation"):
                st.markdown("**Remediation:**")
                st.warning(f.get("remediation"))

            # AI explanation
            if f.get("ai_explanation"):
                st.markdown("**AI draft** *(unverified prose; review claims against evidence)*:")
                st.info(f.get("ai_explanation"))

            # Notes
            notes = f.get("notes", [])
            if notes:
                st.markdown("**Notes from agents:**")
                for note in notes:
                    st.markdown(f"- {note}")


def _render_graph(ctx) -> None:
    graph = ctx.state.get("graph", {})
    if not graph:
        return

    st.subheader("🕸️ Dependency Graph")
    g_sum = graph.get("summary", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Components", g_sum.get("total_components", "—"))
    c2.metric("Direct",           g_sum.get("direct", "—"))
    c3.metric("Transitive",       g_sum.get("transitive", "—"))
    c4.metric("Max Depth",        g_sum.get("max_depth", "—"))

    html_path = graph.get("graph_html")
    if html_path and Path(html_path).exists():
        if hasattr(st, "iframe"):
            st.iframe(Path(html_path), height=600, alt="Interactive dependency graph")
        else:
            html_content = Path(html_path).read_text(encoding="utf-8")
            st.components.v1.html(html_content, height=600, scrolling=True)
    else:
        st.info("Graph HTML not available.")


def _render_downloads(ctx, md_path: str | None, json_path: str | None) -> None:
    st.subheader("📥 Download Reports")

    col1, col2 = st.columns(2)
    if md_path and Path(md_path).exists():
        with col1:
            md_bytes = Path(md_path).read_bytes()
            st.download_button(
                "⬇️ Download Markdown Report",
                data=md_bytes,
                file_name="guardian_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
    if json_path and Path(json_path).exists():
        with col2:
            json_bytes = Path(json_path).read_bytes()
            st.download_button(
                "⬇️ Download JSON Report",
                data=json_bytes,
                file_name="guardian_report.json",
                mime="application/json",
                use_container_width=True,
            )


def _render_logs(ctx) -> None:
    with st.expander("🗒️ Agent Log"):
        for entry in ctx.log:
            st.markdown(f"**[{entry['agent']}]** {entry['message']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    _init_state()

    # Header
    st.markdown(
        """
        <div class="guardian-header">
            <h1>🛡️ Guardian AI</h1>
            <p>Agentic Software Supply Chain Security Scanner</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar
    repo_to_scan = _sidebar()

    # Trigger scan
    if repo_to_scan:
        with st.spinner(f"Running Guardian AI pipeline on `{repo_to_scan}` …"):
            _run_pipeline(repo_to_scan)
        if st.session_state.run_error:
            err = st.session_state.run_error
            st.error(f"❌ Pipeline failed: {err['message']}")
            with st.expander("Show full traceback"):
                st.code(err["traceback"], language="python")
        else:
            st.success("✅ Scan complete!")

    # Display results
    ctx = st.session_state.ctx
    if ctx is not None and st.session_state.run_error is None:
        tabs = st.tabs(["📊 Summary", "🔎 Findings", "🕸️ Graph", "📥 Downloads", "🗒️ Logs"])
        with tabs[0]:
            _render_summary(ctx)
        with tabs[1]:
            _render_findings(ctx)
        with tabs[2]:
            _render_graph(ctx)
        with tabs[3]:
            _render_downloads(ctx, st.session_state.md_path, st.session_state.json_path)
        with tabs[4]:
            _render_logs(ctx)
    elif ctx is None and st.session_state.run_error is None:
        # Welcome / instructions
        st.info(
            "👈 Enter a public GitHub URL in the sidebar and click **Run Scan** to start."
        )
        st.markdown(
            """
### How it works

1. **Recon Agent** – clones the repo and identifies ecosystems, Dockerfiles, CI workflows.
2. **SBOM & Graph Agent** – generates a CycloneDX SBOM and builds a dependency graph.
3. **Vulnerability Agent** – matches SBOM components with Grype and traces dependency paths.
4. **Suspicious Change Agent** – checks npm package metadata and lockfile changes.
5. **Container & CI Agent** – inspects Docker, Compose, and GitHub workflow files.
6. **Evidence & Risk Agent** – validates findings and assigns initial risk levels.
7. **Report Generator** – produces Markdown and JSON reports.

### Responsible AI

- Risk levels are computed **deterministically** — never by an AI model.
- Optional Groq calls suggest unknown manifests and explain a few existing findings.
- AI prose with new CVE IDs is discarded; other claims still need human review.
- API keys are **never** logged, displayed, or stored in reports.

### Prerequisites

```bash
./.venv/Scripts/python.exe -m pip install -r requirements.txt
# cdxgen must be installed and available on PATH
cdxgen --version
grype version
```
            """
        )


if __name__ == "__main__":
    main()
