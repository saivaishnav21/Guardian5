# Software Supply Chain Guardian

The current pipeline clones a public GitHub repository, inventories known project files,
generates a CycloneDX SBOM with cdxgen, exports a dependency graph, and runs the
suspicious-change agent. Vulnerability and container/CI scanning are not yet connected
to the pipeline.

## Setup (PowerShell)

Install Python 3.12+, Git, and cdxgen, then run from this repository's root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm install -g @cdxgen/cdxgen --omit=optional --ignore-scripts --min-release-age=2
```

The npm installation of current cdxgen requires Node.js 24+. A standalone cdxgen
executable on `PATH` also works.

## Optional Groq recon fallback

Put your key in the gitignored `.env` file:

```text
GROQ_API_KEY=your-key-here
GROQ_MODEL=openai/gpt-oss-20b
```

Recon uses fixed rules for recognised manifests. If a key is present, it sends up to
200 paths of other likely manifest files to Groq. Only repository-relative filenames
are sent, not file contents. Suggestions appear under `ai_recon` in `recon.json` and
are marked `verified: false`. They do not create dependencies or alter the SBOM.
If the key is absent or the API fails, the deterministic scan continues.

## Run

```powershell
.\.venv\Scripts\python.exe -m guardian.cli https://github.com/OWASP/NodeGoat.git
```

Replace the URL with another public GitHub repository. Run outputs are written under
`runs/`. NodeGoat is an example target, not a required input.

## Contributing

Fetch and review `origin/main` before integrating teammate work. Make changes on a
feature branch and open a pull request instead of pushing directly to `main`. Keep
real API keys in `.env`; only `.env.example` belongs in Git. Generated `runs/`,
`target/`, and `out/` directories are ignored. Existing tracked cache files must
be removed from Git's index separately because ignore rules do not untrack them.
