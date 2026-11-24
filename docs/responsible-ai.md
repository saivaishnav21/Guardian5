# Responsible AI and security

- Evidence comes from the cloned repository, CycloneDX SBOM, Grype output,
  static Dockerfile/Compose/CI checks, and optional Trivy output for a local image.
  Groq suggestions are marked unverified.
- The initial risk level follows the detector's severity. Exploitability,
  reachability, exposure, and provenance are not established by this prototype.
- Groq can suggest ecosystems from filenames and explain up to five findings in
  prose. Its text cannot create a finding or change the final risk level. New CVE
  IDs in generated prose are rejected; other statements still need human review.
- The recon call sends only repository-relative filenames. The explanation call
  sends a limited finding summary and selected evidence fields, never raw source
  lines or the API key. These are still external API requests; use no key when
  scanning repositories whose metadata must stay local.
- Store `GROQ_API_KEY` in the gitignored `.env` file or environment. Never commit
  keys, raw secrets, or generated run directories.
- Only public GitHub repositories are accepted by the current recon agent. The
  scanner does not automatically modify, merge, or deploy a target. Human approval
  is required before any remediation in a later phase.
- Missing Grype, failed scans, and components without a graph path are limitations
  to review, not evidence that a repository is safe.
