import argparse

from guardian.orchestrator import run_pipeline

def main():
    ap = argparse.ArgumentParser(description="Software Supply Chain Guardian")
    ap.add_argument("repo_url", help="public GitHub repo URL to scan")
    args = ap.parse_args()
    run_pipeline(args.repo_url)


if __name__ == "__main__":
    main()
