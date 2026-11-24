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
    GROQ_API_KEY=<key>   – enables optional AI advisory in the Evidence
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
from guardian.approval_gate import (
    create_preflight_review, load_proposals, may_auto_trial, may_trial, proposal_sha256,
    save_preflight_review, trial_route,
)
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
    /* =========================================================
       GUARDIAN AI — Premium Dark Cybersecurity SaaS Theme
       All selectors target semantic HTML produced by Streamlit
       or custom class names injected by this app only.
       No fragile generated class names are used.
    ========================================================= */

    /* ── Design tokens ─────────────────────────────────────── */
    :root {
        --bg-base:        #0a0d14;
        --bg-surface:     #0f1420;
        --bg-elevated:    #141926;
        --bg-card:        #161c2e;
        --bg-hover:       #1a2238;

        --border-subtle:  #1e2a42;
        --border-muted:   #263352;
        --border-accent:  #2a4080;

        --cyan:           #00d4ff;
        --cyan-dim:       #0096b8;
        --cyan-glow:      rgba(0, 212, 255, 0.15);
        --blue:           #3b82f6;
        --blue-dim:       #2563eb;

        --text-primary:   #e2e8f4;
        --text-secondary: #8899bb;
        --text-muted:     #4a5a7a;
        --text-code:      #7dd3fc;

        --critical:       #f43f5e;
        --critical-bg:    rgba(244,  63,  94, 0.12);
        --high:           #f97316;
        --high-bg:        rgba(249, 115,  22, 0.12);
        --medium:         #eab308;
        --medium-bg:      rgba(234, 179,   8, 0.12);
        --low:            #22c55e;
        --low-bg:         rgba( 34, 197,  94, 0.12);
        --unrated:        #64748b;
        --unrated-bg:     rgba(100, 116, 139, 0.12);

        --radius-sm:  6px;
        --radius-md:  10px;
        --radius-lg:  14px;

        --shadow-card: 0 4px 24px rgba(0,0,0,0.5), 0 1px 4px rgba(0,0,0,0.3);
        --shadow-glow: 0 0 20px rgba(0,212,255,0.08);
    }

    /* ── Global app background & font ──────────────────────── */
    html, body, [data-testid="stAppViewContainer"],
    [data-testid="stApp"] {
        background-color: var(--bg-base) !important;
        color: var(--text-primary) !important;
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif !important;
        font-size: 14px;
    }

    /* Main content area */
    [data-testid="stMain"],
    section[data-testid="stMainContent"],
    .main .block-container {
        background-color: var(--bg-base) !important;
        padding-top: 1.5rem !important;
        padding-bottom: 3rem !important;
        max-width: 1280px;
    }

    /* ── Sidebar ────────────────────────────────────────────── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1120 0%, #0a0e1a 100%) !important;
        border-right: 1px solid var(--border-subtle) !important;
    }
    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.5rem;
    }
    /* Sidebar title */
    [data-testid="stSidebar"] h1 {
        color: var(--cyan) !important;
        font-size: 1.3rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.04em;
        text-shadow: 0 0 20px var(--cyan-glow);
        margin-top: 0.4rem !important;
    }
    /* Sidebar caption / subtitle */
    [data-testid="stSidebar"] .stCaption,
    [data-testid="stSidebar"] small {
        color: var(--text-muted) !important;
        font-size: 0.75rem !important;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }
    /* Sidebar subheader */
    [data-testid="stSidebar"] h3 {
        color: var(--text-primary) !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--text-secondary) !important;
        margin-top: 0.75rem !important;
    }
    /* Sidebar divider */
    [data-testid="stSidebar"] hr {
        border-color: var(--border-subtle) !important;
        margin: 1rem 0 !important;
    }

    /* ── Text inputs ────────────────────────────────────────── */
    input[type="text"],
    input[type="number"],
    textarea,
    [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-muted) !important;
        border-radius: var(--radius-sm) !important;
        color: var(--text-primary) !important;
        font-size: 0.85rem !important;
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="text"]:focus,
    input[type="number"]:focus,
    textarea:focus,
    [data-testid="stTextInput"] input:focus,
    [data-testid="stNumberInput"] input:focus {
        border-color: var(--cyan) !important;
        box-shadow: 0 0 0 3px var(--cyan-glow) !important;
        outline: none !important;
    }
    /* Input label */
    [data-testid="stTextInput"] label,
    [data-testid="stNumberInput"] label,
    [data-testid="stMultiSelect"] label {
        color: var(--text-secondary) !important;
        font-size: 0.75rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }

    /* ── Multiselect ────────────────────────────────────────── */
    [data-testid="stMultiSelect"] [data-baseweb="select"] > div {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-muted) !important;
        border-radius: var(--radius-sm) !important;
        color: var(--text-primary) !important;
    }
    /* Multiselect tags */
    [data-baseweb="tag"] {
        background: var(--border-accent) !important;
        border-radius: 4px !important;
        color: var(--text-primary) !important;
        font-size: 0.72rem !important;
    }

    /* ── Buttons ────────────────────────────────────────────── */
    /* Primary button (Run Scan) */
    [data-testid="stButton"] > button[kind="primary"],
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #0369a1 0%, #0ea5e9 100%) !important;
        border: none !important;
        border-radius: var(--radius-sm) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        font-size: 0.85rem !important;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        padding: 0.6rem 1.2rem !important;
        box-shadow: 0 4px 14px rgba(14,165,233,0.35) !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stButton"] > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #0ea5e9 0%, #38bdf8 100%) !important;
        box-shadow: 0 6px 20px rgba(14,165,233,0.5) !important;
        transform: translateY(-1px) !important;
    }
    /* Secondary / quick-pick buttons */
    [data-testid="stButton"] > button[kind="secondary"],
    .stButton > button[kind="secondary"],
    [data-testid="stButton"] > button:not([kind]) {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-muted) !important;
        border-radius: var(--radius-sm) !important;
        color: var(--text-secondary) !important;
        font-size: 0.78rem !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stButton"] > button:not([kind="primary"]):hover {
        background: var(--bg-hover) !important;
        border-color: var(--cyan-dim) !important;
        color: var(--cyan) !important;
    }
    /* Download button */
    [data-testid="stDownloadButton"] > button {
        background: var(--bg-elevated) !important;
        border: 1px solid var(--border-accent) !important;
        border-radius: var(--radius-sm) !important;
        color: var(--cyan) !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
        letter-spacing: 0.03em;
        transition: all 0.2s ease !important;
    }
    [data-testid="stDownloadButton"] > button:hover {
        background: var(--cyan-glow) !important;
        border-color: var(--cyan) !important;
        box-shadow: 0 0 12px var(--cyan-glow) !important;
    }

    /* ── Tabs ───────────────────────────────────────────────── */
    [data-testid="stTabs"] [role="tablist"] {
        background: var(--bg-surface) !important;
        border-bottom: 1px solid var(--border-subtle) !important;
        gap: 0 !important;
        padding: 0 0.5rem !important;
    }
    [data-testid="stTabs"] [role="tab"] {
        color: var(--text-muted) !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.05em;
        padding: 0.75rem 1.1rem !important;
        border-bottom: 2px solid transparent !important;
        border-radius: 0 !important;
        background: transparent !important;
        transition: color 0.2s, border-color 0.2s;
    }
    [data-testid="stTabs"] [role="tab"]:hover {
        color: var(--text-secondary) !important;
        background: var(--bg-hover) !important;
    }
    [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
        color: var(--cyan) !important;
        border-bottom-color: var(--cyan) !important;
        background: transparent !important;
    }

    /* ── Expanders ──────────────────────────────────────────── */
    [data-testid="stExpander"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-md) !important;
        margin-bottom: 0.6rem !important;
        overflow: hidden;
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    [data-testid="stExpander"]:hover {
        border-color: var(--border-accent) !important;
        box-shadow: var(--shadow-card) !important;
    }
    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] [data-testid="stExpanderToggleIcon"] {
        color: var(--text-secondary) !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
        padding: 0.75rem 1rem !important;
    }
    [data-testid="stExpander"] summary:hover {
        color: var(--text-primary) !important;
        background: var(--bg-hover) !important;
    }
    [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        background: var(--bg-card) !important;
        border-top: 1px solid var(--border-subtle) !important;
        padding: 1rem !important;
    }

    /* ── Metric cards (st.metric) ───────────────────────────── */
    [data-testid="stMetric"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-md) !important;
        padding: 1.1rem 1.3rem !important;
        box-shadow: var(--shadow-card) !important;
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    [data-testid="stMetric"]:hover {
        border-color: var(--border-accent) !important;
        box-shadow: var(--shadow-card), var(--shadow-glow) !important;
    }
    [data-testid="stMetricLabel"] {
        color: var(--text-muted) !important;
        font-size: 0.7rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.1em;
        text-transform: uppercase !important;
    }
    [data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-size: 2rem !important;
        font-weight: 800 !important;
        line-height: 1.1;
        letter-spacing: -0.02em;
    }

    /* ── Alert / notification boxes ─────────────────────────── */
    [data-testid="stAlert"],
    .stAlert {
        border-radius: var(--radius-md) !important;
        border-width: 1px !important;
        font-size: 0.84rem !important;
    }
    /* info */
    [data-testid="stAlert"][data-type="info"],
    .element-container .stAlert.info {
        background: rgba(59,130,246,0.1) !important;
        border-color: rgba(59,130,246,0.3) !important;
        color: #93c5fd !important;
    }
    /* warning */
    [data-testid="stAlert"][data-type="warning"],
    .element-container .stAlert.warning {
        background: var(--medium-bg) !important;
        border-color: rgba(234,179,8,0.3) !important;
        color: #fde68a !important;
    }
    /* error */
    [data-testid="stAlert"][data-type="error"],
    .element-container .stAlert.error {
        background: var(--critical-bg) !important;
        border-color: rgba(244,63,94,0.3) !important;
        color: #fca5a5 !important;
    }
    /* success */
    [data-testid="stAlert"][data-type="success"],
    .element-container .stAlert.success {
        background: var(--low-bg) !important;
        border-color: rgba(34,197,94,0.3) !important;
        color: #86efac !important;
    }

    /* ── Code blocks ────────────────────────────────────────── */
    [data-testid="stCode"],
    code, pre {
        background: #0a0f1c !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-sm) !important;
        color: var(--text-code) !important;
        font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace !important;
        font-size: 0.8rem !important;
    }
    p code, li code {
        background: rgba(125, 211, 252, 0.1) !important;
        border: 1px solid rgba(125, 211, 252, 0.2) !important;
        padding: 0.1em 0.4em !important;
        border-radius: 3px !important;
        font-size: 0.82em !important;
    }

    /* ── JSON viewer ────────────────────────────────────────── */
    [data-testid="stJson"] {
        background: #080c18 !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-sm) !important;
        padding: 0.8rem !important;
        font-size: 0.78rem !important;
    }

    /* ── Spinner ────────────────────────────────────────────── */
    [data-testid="stSpinner"] {
        color: var(--cyan) !important;
    }
    [data-testid="stSpinner"] > div {
        border-top-color: var(--cyan) !important;
    }

    /* ── Headings ───────────────────────────────────────────── */
    h1, h2, h3 {
        color: var(--text-primary) !important;
    }
    h2 {
        font-size: 1.1rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.03em;
        border-bottom: 1px solid var(--border-subtle);
        padding-bottom: 0.5rem;
        margin-top: 1.5rem !important;
    }
    h3 {
        font-size: 1rem !important;
        font-weight: 600 !important;
        color: var(--text-secondary) !important;
    }

    /* ── Dividers ───────────────────────────────────────────── */
    hr {
        border-color: var(--border-subtle) !important;
    }

    /* ── Caption / small text ───────────────────────────────── */
    .stCaption, small, [data-testid="stCaptionContainer"] {
        color: var(--text-muted) !important;
        font-size: 0.72rem !important;
    }

    /* ── Markdown body ──────────────────────────────────────── */
    [data-testid="stMarkdownContainer"] p {
        color: var(--text-secondary) !important;
        line-height: 1.65;
    }
    [data-testid="stMarkdownContainer"] strong {
        color: var(--text-primary) !important;
        font-weight: 600;
    }
    [data-testid="stMarkdownContainer"] li {
        color: var(--text-secondary) !important;
        line-height: 1.7;
    }

    /* ── Image (sidebar logo) ───────────────────────────────── */
    [data-testid="stSidebar"] [data-testid="stImage"] img {
        filter: drop-shadow(0 0 10px rgba(0,212,255,0.3));
        margin-bottom: 0.25rem;
    }

    /* =========================================================
       Custom class overrides (injected by this app via
       st.markdown unsafe_allow_html=True)
    ========================================================= */

    /* ── Guardian header banner ─────────────────────────────── */
    .guardian-header {
        background: linear-gradient(135deg, #060a14 0%, #0a1628 40%, #0d2044 100%);
        padding: 2.5rem 2rem;
        border-radius: var(--radius-lg);
        margin-bottom: 2rem;
        text-align: center;
        color: white;
        border: 1px solid var(--border-subtle);
        box-shadow: var(--shadow-card), inset 0 1px 0 rgba(255,255,255,0.03);
        position: relative;
        overflow: hidden;
    }
    .guardian-header::before {
        content: '';
        position: absolute;
        top: -1px; left: -1px; right: -1px; bottom: -1px;
        background: linear-gradient(135deg,
            rgba(0,212,255,0.08) 0%,
            transparent 50%,
            rgba(59,130,246,0.05) 100%);
        pointer-events: none;
        border-radius: inherit;
    }
    .guardian-header h1 {
        font-size: 2.6rem !important;
        font-weight: 800 !important;
        margin: 0 !important;
        letter-spacing: -0.02em;
        background: linear-gradient(135deg, #ffffff 30%, var(--cyan) 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    .guardian-header p {
        opacity: 0.65;
        margin-top: 0.5rem !important;
        font-size: 0.9rem !important;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--text-secondary);
        -webkit-text-fill-color: unset;
    }

    /* ── Metric card (custom HTML cards, if used) ───────────── */
    .metric-card {
        background: var(--bg-card);
        border-radius: var(--radius-md);
        padding: 1.1rem 1.4rem;
        border-left: 3px solid var(--border-accent);
        margin-bottom: 0.75rem;
        box-shadow: var(--shadow-card);
        transition: transform 0.15s, box-shadow 0.15s;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: var(--shadow-card), var(--shadow-glow);
    }
    .risk-critical { border-left-color: var(--critical) !important; }
    .risk-high     { border-left-color: var(--high)     !important; }
    .risk-medium   { border-left-color: var(--medium)   !important; }
    .risk-low      { border-left-color: var(--low)      !important; }
    .risk-unrated  { border-left-color: var(--unrated)  !important; }

    /* ── Finding card ───────────────────────────────────────── */
    .finding-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
        padding: 1.2rem 1.4rem;
        margin-bottom: 0.75rem;
        box-shadow: var(--shadow-card);
        transition: border-color 0.2s, transform 0.15s;
    }
    .finding-card:hover {
        border-color: var(--border-accent);
        transform: translateY(-1px);
    }

    /* ── Severity badges ────────────────────────────────────── */
    .badge {
        display: inline-block;
        padding: 0.2em 0.65em;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: white;
        line-height: 1.4;
    }
    .badge-critical {
        background: var(--critical);
        box-shadow: 0 2px 8px rgba(244,63,94,0.4);
    }
    .badge-high {
        background: var(--high);
        box-shadow: 0 2px 8px rgba(249,115,22,0.35);
    }
    .badge-medium {
        background: var(--medium);
        color: #0a0d14;
        box-shadow: 0 2px 8px rgba(234,179,8,0.3);
    }
    .badge-low {
        background: var(--low);
        box-shadow: 0 2px 8px rgba(34,197,94,0.3);
    }
    .badge-unrated {
        background: var(--unrated);
        color: #e2e8f4;
    }

    /* ── Scrollbar ──────────────────────────────────────────── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-base); }
    ::-webkit-scrollbar-thumb {
        background: var(--border-accent);
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover { background: var(--cyan-dim); }
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
        "repo_input": _SAMPLE_REPOS[0],
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

def _select_repo(repo_url: str) -> None:
    st.session_state.repo_input = repo_url


def _sidebar() -> str | None:
    """Render sidebar. Returns repo URL to scan or None."""
    with st.sidebar:
        st.markdown("# 🛡️")
        st.title("Guardian AI")
        st.caption("Software Supply Chain Guardian")
        st.divider()

        st.subheader("🔍 Scan a Repository")
        repo_url = st.text_input(
            "Public GitHub URL",
            key="repo_input",
            placeholder="https://github.com/owner/repo.git",
        )

        st.caption("Quick picks:")
        for sample in _SAMPLE_REPOS:
            st.button(sample.split("/")[-1].replace(".git", ""), key=f"btn_{sample}",
                      on_click=_select_repo, args=(sample,))

        if groq_key():
            st.success("🤖 AI key configured")
        else:
            st.info("🤖 AI advisory unavailable. Evidence based ranking and proposals still run.")

        st.divider()
        st.caption("Scan → prioritize → propose → review")

        runs_root = Path(__file__).resolve().parents[1] / "runs"
        saved_runs = sorted((p for p in runs_root.glob("*/state.json") if p.is_file()),
                            key=lambda p: p.parent.name, reverse=True)
        if saved_runs:
            selected = st.selectbox("Open a saved scan", [None, *saved_runs],
                                    format_func=lambda p: "Choose a run" if p is None else p.parent.name)
            if st.button("Open saved scan", disabled=selected is None, use_container_width=True):
                _open_saved_run(selected)

        scan_clicked = st.button("🚀 Run Scan", type="primary", use_container_width=True)
        return repo_url.strip() if scan_clicked else None


def _open_saved_run(state_path: Path) -> None:
    """Restore only a completed local run; do not scan or change its baseline."""
    from guardian.agents.base import RunContext

    try:
        saved = json.loads(state_path.read_text(encoding="utf-8"))
        state = saved["state"]
        repo_url = state["recon"]["repo_url"]
        report_path = state_path.parent / "report.json"
        if not report_path.is_file():
            raise ValueError("this run has no completed report")
        ctx = RunContext(repo_url=repo_url, run_dir=state_path.parent,
                         state=state, log=saved.get("log", []))
        st.session_state.ctx = ctx
        st.session_state.md_path = str(state_path.parent / "report.md")
        st.session_state.json_path = str(report_path)
        st.session_state.run_error = None
        st.session_state.last_repo = repo_url
    except (OSError, ValueError, KeyError, TypeError) as exc:
        st.session_state.run_error = {"message": f"Could not open saved run: {exc}", "traceback": ""}


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

    # Review order may be raised by AI; scanner risk is displayed separately.
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _RISK_ORDER.get(f.get("review_priority", f.get("risk_level", "unrated")), 99),
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

            risk_ai = f.get("ai_assessment") or {}
            suspicious_ai = f.get("ai_suspicious") or {}
            if risk_ai.get("status") == "completed" or suspicious_ai.get("status") == "completed":
                st.markdown("**🤖 AI Advisory — not verified**")
                if risk_ai.get("status") == "completed":
                    st.info(f"Suggested review priority: {risk_ai['priority']}. {risk_ai['reason']}")
                    st.caption("Evidence references: " + ", ".join(risk_ai["evidence_refs"])
                               + "; unknown: " + (", ".join(risk_ai["unknowns"]) or "none listed"))
                if suspicious_ai.get("status") == "completed":
                    st.info(f"Hypothesis: {suspicious_ai['hypothesis']}")
                    st.caption(f"Check next: {suspicious_ai['check_next']}; evidence references: "
                               + ", ".join(suspicious_ai["evidence_refs"]))

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

    for filename, label in (
        ("risk_assessment.json", "Download risk assessment"),
        ("proposals.json", "Download proposals"),
        ("approval.json", "Download latest review"),
    ):
        path = ctx.run_dir / filename
        if path.is_file():
            st.download_button(label, data=path.read_bytes(), file_name=filename,
                               mime="application/json", key=f"download_{filename}")


def _render_logs(ctx) -> None:
    with st.expander("🗒️ Agent Log"):
        for entry in ctx.log:
            st.markdown(f"**[{entry['agent']}]** {entry['message']}")


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        st.error(f"Could not read {path.name}: {exc}")
        return None


def _select_item(items: list[dict], label: str, key: str) -> dict | None:
    if not items:
        st.info("No items are available for this run.")
        return None
    index = st.selectbox(
        label, range(len(items)), key=key,
        format_func=lambda i: (
            f"#{items[i].get('rank', i + 1)} · "
            f"{items[i].get('finding_id', (items[i].get('finding_ids') or ['?'])[0])} · "
            f"{items[i].get('component', '?')}"
        ),
    )
    return items[index]


def render_risks(run_dir: Path) -> None:
    st.subheader("Prioritized risks")
    st.caption("Evidence based ranking for this repository and commit. AI advice is separate from the score.")
    path = run_dir / "risk_assessment.json"
    if not path.is_file():
        st.info("Risk assessment has not been generated for this run.")
        return
    data = _read_json(path)
    if not isinstance(data, dict):
        return
    items = data.get("items", [])
    if not isinstance(items, list):
        st.error("Risk assessment items are invalid.")
        return
    counts = (data.get("summary") or {}).get("by_level") or {}
    cols = st.columns(4)
    for col, level in zip(cols, ("critical", "high", "medium", "low")):
        col.metric(level.title(), counts.get(level, 0))
    st.dataframe([{
        "Rank": item.get("rank"), "Score": item.get("risk_score"),
        "Level": item.get("risk_level"), "Component": item.get("component"),
        "Finding": item.get("title"),
    } for item in items], hide_index=True, width="stretch")
    item = _select_item(items, "Inspect ranked risk", "risk_detail_choice")
    if item:
        st.write(item.get("rationale") or "No scoring rationale recorded.")
        st.caption("Evidence: " + ", ".join(item.get("evidence_refs") or []))
        if item.get("unknowns"):
            st.warning("Unknowns: " + "; ".join(item["unknowns"]))
        advisory = item.get("ai_advisory")
        if advisory:
            st.info("🤖 AI Advisory — not verified")
            st.write(advisory.get("reason") or advisory.get("hypothesis") or "No explanation recorded.")
        with st.expander("Scoring details"):
            st.json(item.get("score_breakdown") or [])


def _proposal_detail(proposal: dict) -> None:
    result = proposal.get("result", "unknown")
    st.markdown(f"**{proposal.get('component', '?')} · {result.replace('_', ' ').title()}**")
    cols = st.columns(3)
    cols[0].metric("Risk score", proposal.get("risk_score", "—"))
    cols[1].metric("Proposed version", proposal.get("target_version") or "None recorded")
    cols[2].metric("Proposal confidence", f"{proposal.get('confidence_score', 0)}/100")
    st.caption("Proposal confidence reflects recorded evidence, not compatibility or permission to apply a change.")
    route = trial_route(proposal)
    st.caption(f"Sandbox routing threshold: {route['threshold']}/100 · "
               f"{'Automatic trial candidate' if route['route'] == 'auto_sandbox_trial' else 'Human review required'}")
    if proposal.get("reason"):
        st.warning(proposal["reason"])
    if proposal.get("manifest_file"):
        st.write(f"**Manifest:** `{proposal['manifest_file']}`")
    if proposal.get("command"):
        st.caption("Candidate command for a future sandbox trial. This screen never runs it.")
        st.code(proposal["command"], language="bash")
    if proposal.get("compatibility_concern"):
        st.caption(proposal["compatibility_concern"])
    if proposal.get("llm_explanation_status") == "completed_unverified":
        st.info("🤖 AI Advisory — not verified")
        st.write(proposal.get("llm_explanation", ""))
    with st.expander("Evidence, limits, and rollback"):
        st.write("**Evidence:** " + (", ".join(proposal.get("evidence_refs") or []) or "None recorded"))
        st.write("**Unknowns:** " + ("; ".join(proposal.get("unknowns") or []) or "None recorded"))
        st.write("**Rollback:** " + str(proposal.get("rollback") or "No change has been applied"))
        st.write("**Confidence factors:** " + "; ".join(proposal.get("confidence_reasons") or []))


def _load_proposals(run_dir: Path) -> tuple[Path, list[dict]] | None:
    source = run_dir / "proposals.json"
    if not source.is_file():
        st.info("Proposals have not been generated for this run.")
        return None
    try:
        return source, load_proposals(source)
    except (OSError, ValueError) as exc:
        st.error(f"Could not read proposals.json: {exc}")
        return None


def render_proposals(run_dir: Path) -> None:
    st.subheader("Proposed fixes")
    st.caption("A proposal is a candidate action. Build, tests, and rescan have not yet verified it.")
    loaded = _load_proposals(run_dir)
    if loaded is None:
        return
    _, proposals = loaded
    cols = st.columns(4)
    for col, result, label in zip(cols[:3],
                                  ("upgrade", "manual_review", "mitigation_only"),
                                  ("Upgrade candidates", "Manual review", "Mitigation only")):
        col.metric(label, sum(p.get("result") == result for p in proposals))
    cols[3].metric("Automatic sandbox route", sum(trial_route(p)["route"] == "auto_sandbox_trial"
                                                   for p in proposals))
    filter_result = st.selectbox("Show", ["all", "upgrade", "manual_review", "mitigation_only"],
                                 format_func=lambda x: x.replace("_", " ").title())
    shown = [p for p in proposals if filter_result == "all" or p.get("result") == filter_result]
    st.dataframe([{
        "Finding": p.get("finding_id"), "Component": p.get("component"),
        "Risk": p.get("risk_level"), "Action": p.get("result"),
        "Target": p.get("target_version") or "—",
        "Trial route": trial_route(p)["route"].replace("_", " "),
    } for p in shown], hide_index=True, width="stretch")
    proposal = _select_item(shown, "Inspect proposal", "proposal_detail_choice")
    if proposal:
        _proposal_detail(proposal)


def render_approval(run_dir: Path) -> None:
    st.subheader("Human review")
    st.caption("Review the current run's proposal. Approval permits a sandbox trial only; it does not apply or adopt a fix.")
    loaded = _load_proposals(run_dir)
    report_path = run_dir / "report.json"
    if loaded is None or not report_path.is_file():
        st.info("A completed report and proposals are required before review.")
        return
    source, proposals = loaded
    report = _read_json(report_path)
    if not isinstance(report, dict):
        return
    routes = ["auto_sandbox_trial", "manual_review", "all"]
    if not any(trial_route(p)["route"] == "auto_sandbox_trial" for p in proposals):
        routes = ["manual_review", "all"]
    review_filter = st.selectbox("Review queue", routes,
                                 format_func=lambda value: value.replace("_", " ").title())
    review_items = [p for p in proposals if review_filter == "all"
                    or trial_route(p)["route"] == review_filter]
    proposal = _select_item(review_items, "Proposal to review", "approval_proposal_choice")
    if proposal is None:
        return
    _proposal_detail(proposal)
    header = report.get("guardian_report") or {}
    st.caption(f"Baseline: {header.get('repo_url', '?')} · {header.get('commit', '?')}")

    route = trial_route(proposal)
    auto_ready = False
    if route["route"] == "auto_sandbox_trial":
        blocks = may_auto_trial(proposal, report, source)
        if blocks:
            st.warning("Automatic sandbox trial blocked: " + "; ".join(blocks))
        else:
            auto_ready = True
            st.success("Automatically eligible for a disposable sandbox trial. No human preflight approval is needed.")
            st.caption("This is not approval to apply or adopt the fix. Tests, rescan, and a final human decision are still required.")
    else:
        st.info(f"Human preflight review required. {route['reason']}")

    history_path = run_dir / "approvals.json"
    if history_path.is_file():
        history = _read_json(history_path)
        if isinstance(history, list):
            previous = next((r for r in reversed(history) if isinstance(r, dict)
                             and r.get("proposal_sha256") == proposal_sha256(proposal)), None)
            if previous:
                st.info(f"Latest decision: {previous.get('decision', 'unknown')} · {previous.get('reviewed_at', '?')}")
                if previous.get("decision") == "approve":
                    blocks = may_trial(previous, proposal, report, source)
                    st.caption("Sandbox gate: permitted" if not blocks else "Sandbox gate: blocked — " + "; ".join(blocks))

    st.warning("No patch or test result is attached. Final adoption is unavailable.")
    if auto_ready:
        st.caption("Optional human override: reject this candidate or request changes before a trial.")
    decisions = ["request_changes", "reject"]
    if proposal.get("result") == "upgrade" and not auto_ready:
        decisions.append("approve")
    with st.form("human_approval_form"):
        decision = st.selectbox("Decision", decisions,
                                format_func=lambda value: "Approve sandbox trial" if value == "approve"
                                else value.replace("_", " ").title())
        reason = st.text_area("Reason for decision", placeholder="State what you checked and what should happen next")
        understood = st.checkbox("I reviewed this proposal and understand no fix is applied here")
        submitted = st.form_submit_button("Record decision", type="primary")
    if submitted:
        if not understood:
            st.error("Confirm the review scope before recording a decision.")
            return
        try:
            review = create_preflight_review(
                proposal=proposal, report=report, source_file=source,
                decision=decision, reason=reason,
            )
            saved = save_preflight_review(review, run_dir)
        except (OSError, ValueError) as exc:
            st.error(f"Review was not recorded: {exc}")
        else:
            st.success(f"Decision recorded in {saved}")
            if decision == "approve":
                blocks = may_trial(review, proposal, report, source)
                st.info("Sandbox gate: permitted" if not blocks else "Sandbox gate: blocked — " + "; ".join(blocks))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    _init_state()

    st.markdown(
        """
        <div class="guardian-header">
            <h1>🛡️ Guardian AI</h1>
            <p>From repository evidence to a reviewable security decision</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    repo_to_scan = _sidebar()
    if repo_to_scan:
        with st.spinner(f"Scanning {repo_to_scan} …"):
            _run_pipeline(repo_to_scan)
        if st.session_state.run_error is None:
            st.success("Scan complete. Review the ranked risks and proposals below.")

    if st.session_state.run_error:
        err = st.session_state.run_error
        st.error(f"Pipeline failed: {err['message']}")
        if err.get("traceback"):
            with st.expander("Technical details"):
                st.code(err["traceback"], language="python")

    ctx = st.session_state.ctx
    if ctx is not None and st.session_state.run_error is None:
        st.caption(f"**Repository:** {ctx.repo_url}  ·  **Commit:** {ctx.state.get('recon', {}).get('commit', '?')}  ·  **Run:** {ctx.run_dir.name}")
        tabs = st.tabs(["Overview", "Prioritized risks", "Proposed fixes", "Human review", "Evidence & downloads"])
        with tabs[0]:
            _render_summary(ctx)
            remediation = ctx.state.get("remediation") or {}
            st.info(f"{(ctx.state.get('risk_assessment') or {}).get('summary', {}).get('ranked_items', 0)} risks ranked · "
                    f"{remediation.get('count', 0)} proposals generated · sandbox validation pending")
        with tabs[1]:
            render_risks(ctx.run_dir)
        with tabs[2]:
            render_proposals(ctx.run_dir)
        with tabs[3]:
            render_approval(ctx.run_dir)
        with tabs[4]:
            _render_findings(ctx)
            _render_graph(ctx)
            _render_downloads(ctx, st.session_state.md_path, st.session_state.json_path)
            _render_logs(ctx)
    elif ctx is None and st.session_state.run_error is None:
        st.subheader("Start with a repository")
        st.write("Enter any public GitHub repository URL in the sidebar and run a scan, or open a saved scan.")
        cols = st.columns(4)
        for col, title, body in zip(cols,
                                    ("1 · Scan", "2 · Prioritize", "3 · Propose", "4 · Review"),
                                    ("Collect dependency and security evidence.",
                                     "Rank findings with an explainable score.",
                                     "Prepare candidate fixes and manual cases.",
                                     "Record a human decision for a sandbox trial.")):
            col.markdown(f"**{title}**\n\n{body}")
        st.caption("🤖 AI Advisory — not verified. Model output is separate from scanner evidence and never approves a fix.")


if __name__ == "__main__":
    main()
