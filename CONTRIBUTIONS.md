# Team 5 -- Contributions

## Guardian AI: Software Supply Chain Security

This document outlines the individual contributions and responsibilities
of all five team members in the development of Guardian AI.

## Team Members and Contributions

### 1. P. Sai Vaishnav Reddy

**Register Number:** BL.EN.U4AIE23120

**Responsibilities:** - Repository setup, reconnaissance and project
structure identification. - SBOM generation and dependency graph
execution. - Main pipeline orchestration and integration of individual
modules. - Pull request management and code integration. - Contextual
risk assessment and security finding prioritization. - Risk scoring
using scanner severity, SBOM scope and supporting scanner evidence. -
Recording unknowns such as reachability, exposure and exploitation
status.

**Files and Outputs:** - `base.py` - `recon.py` - `sbom_graph.py` -
`graph.py` - `sbom.py` - `orchestrator.py` - `risk_assessment.json`

### 2. Akshay Sundar T S

**Register Number:** CB.SC.U4AIE23004

**Responsibilities:** - Integration of Grype or OSV-Scanner for
vulnerability detection. - CVE identification and matching. - Tracing
vulnerabilities to their direct dependencies. - Identification of
available vulnerability fixes. - Development of the remediation proposal
workflow. - Generation of package upgrade recommendations and
mitigation-only actions. - Recording compatibility concerns, rollback
instructions and supporting evidence.

**Files and Outputs:** - `agents/vulnerability.py` - `proposals.json`

### 3. Suriya Dharsaun KG

**Register Number:** CB.AI.U4AID23144

**Responsibilities:** - Typosquatting detection and suspicious package
analysis. - Analysis of npm install scripts and lockfile differences. -
Identification of unusual dependency sources and resolutions. -
Investigation of tampered branches on repository forks. - Investigation
of suspicious non-CVE security findings. - Development of the human
review and approval workflow. - Handling approval, rejection and
request-changes decisions. - Linking approval decisions to proposals and
patch evidence.

**Files and Outputs:** - `agents/suspicious.py` - `investigation.json` -
`approval.json`

### 4. Sanggit Saaran K C S

**Register Number:** CB.SC.U4AIE23247

**Responsibilities:** - Dockerfile and Docker Compose inspection. -
Container image vulnerability scanning using Trivy. - GitHub Actions
workflow security checks using zizmor or actionlint. - Docker sandbox
analysis and identification of container security issues. - Preparation
of isolated sandbox environments. - Execution of baseline and candidate
builds and tests. - Validation of proposed changes in a disposable
workspace. - Recording changed files, commands, environment details and
test logs.

**Files and Outputs:** - `agents/container_ci.py` - `validation.json`

### 5. Sai Charan M

**Register Number:** CB.SC.U4AIE23143

**Responsibilities:** - Development of the evidence validation and risk
assessment components. - LLM-based risk assessment agent. - Guardian
security report generation. - Streamlit dashboard development and
integration. - Architecture diagram preparation and Responsible AI
documentation. - Comparison of baseline and candidate security scans. -
Rescanning the candidate project after proposed remediation. -
Verification of CVE vulnerabilities and non-CVE findings. -
Classification of findings as resolved, remaining, new or unverified. -
Analysis of scan coverage differences. - Generation of evidence-based
verification reports. - Integration of the verification and review
workflow into the Streamlit dashboard.

**Files and Outputs:** - `agents/evidence_risk.py` - `report.py` -
`app.py` - `docs/` - `verification.json`

------------------------------------------------------------------------

## Overall Project Contributions

Together, the team developed Guardian AI as a software supply-chain
security system covering:

1.  **Repository Reconnaissance:** Identifying project structure,
    manifests and configuration files.
2.  **SBOM and Dependency Analysis:** Generating software inventories
    and dependency graphs using cdxgen.
3.  **Vulnerability Detection:** Identifying known vulnerabilities using
    Grype and other scanning tools.
4.  **Suspicious Dependency Analysis:** Detecting typosquatting,
    suspicious install scripts and unusual dependency changes.
5.  **Container and CI/CD Security:** Inspecting Docker configurations,
    container images and GitHub Actions workflows.
6.  **Evidence and Risk Assessment:** Validating findings, prioritizing
    risks and generating security reports.
7.  **Remediation Proposals:** Recommending dependency upgrades and
    mitigation actions.
8.  **Investigation and Human Approval:** Reviewing suspicious findings
    and controlling remediation decisions.
9.  **Sandbox Validation:** Testing proposed changes in an isolated
    environment.
10. **Rescan and Verification:** Comparing baseline and candidate scans
    to determine remediation outcomes.

## Final Outcome

Guardian AI aims to transform software supply-chain security from basic
vulnerability detection into an evidence-driven process that includes
risk prioritization, remediation proposals, isolated testing, rescanning
and human-reviewed verification.

The system is designed to preserve the original repository and keep
final remediation adoption under human control.
