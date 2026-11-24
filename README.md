# Software Supply Chain Guardian

Guardian is a Day 1 supply chain visibility prototype. Give it a **public GitHub repository URL** and it creates a component inventory, dependency graph, security findings, and an evidence-based report. It observes and reports; it does not change the target repository or apply fixes.

## Current stage

The Day 1 pipeline is connected and has been run end to end on OWASP NodeGoat. The CLI and Streamlit app use the same pipeline:

| Stage | What it does | Main output |
| --- | --- | --- |
| Recon | Shallow-clones a public GitHub repo; lists known manifests, Dockerfiles, Compose files, and GitHub Actions workflows | `recon.json` |
| SBOM and graph | Uses cdxgen to create a CycloneDX SBOM; builds and annotates a dependency graph | `sbom.cdx.json`, `graph.json`, `graph.html` |
| Vulnerabilities | Uses Grype to match SBOM components to advisories, fixes, and graph paths when available | `vulnerability.json`, `vulnerability_raw.json` |
| Suspicious changes | Checks npm metadata and lockfiles for install scripts, unusual resolutions, lookalike names, and optional demo-branch changes | `suspicious.json` |
| Container and CI | Checks Dockerfile, Compose, and workflow files; optionally scans an already-built local image with Trivy | `container_ci.json`, optional `trivy_image.json` |
| Evidence and risk | Validates findings, assigns an initial severity-based risk level, and adds remediation guidance | `evidence_risk.json` |
| Risk assessment (Day 2) | Groups duplicate findings and ranks them with a deterministic score from scanner severity plus observed context (scope, image scan, ownership); unmeasured factors are listed as unknowns | `risk_assessment.json` |
| Reporting | Produces a short human-readable summary and a complete machine-readable record | `report.md`, `report.json` |

The Streamlit app runs this pipeline and displays scan coverage, findings in pages of 20, the dependency graph, downloads, and agent logs. It does not implement a separate scanner.

## Setup

You need Python 3.12+, Git, Node.js/npm, cdxgen, and Grype. The version of cdxgen used in our verified run needed Node.js 24; check the requirements of the version you install. Docker and Trivy are optional unless you want to scan a built image.

From the repository root in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm install -g @cdxgen/cdxgen --omit=optional --ignore-scripts --min-release-age=2
winget install Anchore.Grype
# Optional image scanning:
winget install AquaSecurity.Trivy
```

Open a new terminal if a newly installed executable is not yet on `PATH`. Check tools with `cdxgen --version`, `grype version`, `trivy --version`, and `docker version`. On macOS/Linux, create a virtual environment and install the same Python requirements and scanner CLIs using your platform's package manager.

If Grype is missing or fails, the report marks vulnerability matching as incomplete. The SBOM step requires cdxgen; a failure there stops the pipeline.

## Run a scan

```powershell
.\.venv\Scripts\python.exe -m guardian.cli https://github.com/OWASP/NodeGoat.git
```

Replace NodeGoat with another public `https://github.com/<owner>/<repo>` URL. Each run creates an ignored `runs/<timestamp>/` directory. Open `report.md` for the concise overview, `report.json` for **every** finding and its full evidence, and `graph.html` for the dependency view. Raw scanner results and stage status files are in the same directory. Scanner observations may overlap, so the total finding count is not a count of unique security issues.

To use the app:

```powershell
.\.venv\Scripts\python.exe -m streamlit run guardian/app.py
```

The Markdown report shows the top 20 findings, detailed evidence for five, and one example from each detector. The JSON report retains the complete inventory, findings, paths, scan statuses, and evidence. The app lets you filter and page through the full result.

### Optional local-image scan

Guardian does **not** build or pull images automatically. Build an image from the same target commit, install Trivy, and give Guardian its local image tag:

```powershell
git clone https://github.com/OWASP/NodeGoat.git target
docker build --tag guardian-nodegoat-check:local target
$env:GUARDIAN_IMAGE_REF = "guardian-nodegoat-check:local"
.\.venv\Scripts\python.exe -m guardian.cli https://github.com/OWASP/NodeGoat.git
Remove-Item Env:\GUARDIAN_IMAGE_REF
```

`container_ci.json` and the report record whether the image scan completed, was not requested, or could not run. Static Docker/CI checks still run without Docker or Trivy. An image scan does not prove the image came from the scanned commit; build it from that commit for a valid comparison.

### Optional Groq assistance

Copy `.env.example` to the gitignored `.env` file and set `GROQ_API_KEY` there. Without a key, deterministic scanning continues. Recon can send up to 200 repository-relative **filenames** to Groq for unverified manifest suggestions; the suggestions do not add dependencies to the SBOM. The evidence stage can generate drafts for up to five high-priority findings. AI text cannot create a finding or set its risk level. Review all claims in AI prose against recorded evidence before using them.

## Verification and current limits

On 24 November 2026, a local NodeGoat scan at commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` produced 1,096 graph components and 474 findings: 316 Grype vulnerability observations, 148 Trivy image observations, four suspicious-change findings, and six CI findings. These are example results; advisory databases and target commits can change. The Streamlit app loaded that run without an exception.

The NodeGoat Docker image built successfully. Its own `npm test` command did **not** pass inside the production image because that image omits `grunt-cli`, which the test script requires. Guardian does not claim that the sample app's tests pass.

Risk levels currently follow reported severity. The prototype does not establish exploitability, code reachability, exposure, or provenance. Suspicious-change checks focus on npm, and branch comparison is optional. Static Docker/CI rules do not replace a full configuration review. Day 2 remediation, fix validation, and deployment are not implemented.

See [Day 1 architecture](docs/architecture.md) and [Responsible AI and security](docs/responsible-ai.md) for the pipeline, approval points, data handling, and limits.

## Repository hygiene

Keep real API keys in `.env`; only `.env.example` belongs in Git. Generated `runs/`, local `target/`, virtual environment, caches, and scanner output are ignored. Fetch and review `origin/main` before integrating teammate work, then rebase local commits onto the latest `origin/main` before pushing.

