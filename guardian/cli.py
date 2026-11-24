import argparse
import json
from pathlib import Path

from guardian.orchestrator import run_pipeline


def print_summary(ctx):
    findings = ctx.state.get("findings", [])
    suspicious = ctx.state.get("suspicious", {})
    vulnerability = ctx.state.get("vulnerability", {})
    risk_assessment = ctx.state.get("risk_assessment", {})

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

    if risk_assessment:
        summary = risk_assessment.get("summary", {})
        risk_counts = summary.get("by_level", {})
        print(
            "Risk assessment: "
            f"{summary.get('ranked_items', 0)} ranked items "
            f"(critical={risk_counts.get('critical', 0)}, "
            f"high={risk_counts.get('high', 0)}, "
            f"medium={risk_counts.get('medium', 0)}, "
            f"low={risk_counts.get('low', 0)})"
        )
        assessment_path = risk_assessment.get("path")
        if assessment_path:
            print(f"Risk artifact: {assessment_path}")
            try:
                assessment = json.loads(Path(assessment_path).read_text(encoding="utf-8"))
                print("\nTop risk assessments:")
                print("| Rank | Risk | Score | Component | Unknowns |")
                print("|---:|---|---:|---|---|")
                for item in assessment.get("items", [])[:5]:
                    unknown_count = len(item.get("unknowns", []))
                    print(
                        f"| {item.get('rank')} | {item.get('risk_level')} | "
                        f"{item.get('risk_score')} | {item.get('component') or '-'} | "
                        f"{unknown_count} |"
                    )
            except (OSError, json.JSONDecodeError):
                print("Risk artifact: unavailable")

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
