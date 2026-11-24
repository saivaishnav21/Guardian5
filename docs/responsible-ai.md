# Responsible AI and security

- Evidence comes from the cloned repository, CycloneDX SBOM, Grype output,
  static Dockerfile/Compose/CI checks, and optional Trivy output for a local image.
  Groq suggestions are marked unverified.
- The initial risk level follows the detector's severity. Exploitability,
  reachability, exposure, and provenance are not established by this prototype.
- Groq can suggest ecosystems from filenames, review up to six findings for
  priority, and suggest hypotheses and next checks for up to five suspicious
  findings. AI suggestions are labelled **🤖 AI Advisory — not verified**. They
  cannot create findings or change scanner risk; a validated suggestion can only
  raise a finding's review order.
- The recon call sends only repository-relative filenames. Finding review calls
  send a limited finding summary and selected evidence fields, never raw source
  lines or the API key. Responses must cite supplied fields. New CVE IDs,
  versions, and unsupported reachability claims are rejected, but other claims
  still need human review. These are external API requests; use no key when
  scanning repositories whose metadata must stay local.
- AI responses contain an empty `ai_negotiation_log` placeholder for Day 2;
  no agent negotiation is performed in Day 1.
- Day 2 contextual risk scores are deterministic. Existing AI priority advice is
  attached separately where available and cannot change the score. The proposal
  stage may request explanations for at most three bounded direct-npm upgrades;
  these are unverified text and cannot authorize a sandbox trial or adoption.
- Store `GROQ_API_KEY` in the gitignored `.env` file or environment. Never commit
  keys, raw secrets, or generated run directories.
- Only public GitHub repositories are accepted by the current recon agent. The
  scanner does not automatically modify, merge, or deploy a target. Human approval
  is required before any remediation in a later phase.
- Missing Grype, failed scans, and components without a graph path are limitations
  to review, not evidence that a repository is safe.
