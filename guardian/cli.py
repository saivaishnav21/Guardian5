import argparse

from guardian.orchestrator import run_pipeline


def print_summary(ctx):
    findings = ctx.state.get("findings", [])
    suspicious = ctx.state.get("suspicious", {})
    vulnerability = ctx.state.get("vulnerability", {})

    print("\n=== Guardian Summary ===")
    print(f"Graph components: {ctx.state.get('graph', {}).get('summary', {}).get('total_components', 0)}")
    print(f"Suspicious findings: {len([f for f in findings if f.get('type') == 'suspicious_change'])}")
    print(f"Vulnerability findings: {len([f for f in findings if f.get('type') == 'vulnerability'])}")
    print(f"Tampered branch: {suspicious.get('tampered_branch', 'not available')}")

    if vulnerability:
        print(
            "Vulnerability status: "
            f"{vulnerability.get('status', 'unknown')} "
            f"({vulnerability.get('finding_count', 0)} findings)"
        )

    risk = ctx.state.get("risk_assessment", {})
    proposals = ctx.state.get("remediation", {})
    if risk:
        print(f"Prioritized risks: {risk.get('summary', {}).get('ranked_items', 0)} "
              f"({risk.get('path', 'not available')})")
    if proposals:
        print(f"Remediation proposals: {proposals.get('count', 0)} "
              f"{proposals.get('by_result', {})} ({proposals.get('path', 'not available')})")

    print("\nTop findings:")
    shown = 0
    for finding in findings:
        if shown >= 10:
            break
        finding_type = finding.get("type", "unknown")
        severity = finding.get("severity", "unknown")
        component = finding.get("component", "?")
        title = finding.get("title", "")
        print(f"- [{finding_type}] {severity.upper()}: {component} - {title}")
        shown += 1

    if len(findings) > shown:
        print(f"... and {len(findings) - shown} more findings")
    print("========================\n")


def main():
    ap = argparse.ArgumentParser(description="Software Supply Chain Guardian")
    ap.add_argument("repo_url", help="public GitHub repo URL to scan")
    args = ap.parse_args()
    ctx = run_pipeline(args.repo_url)
    print_summary(ctx)


if __name__ == "__main__":
    main()
