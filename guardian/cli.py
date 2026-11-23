import argparse

from guardian.orchestrator import run_pipeline

DEFAULT_REPO = "https://github.com/OWASP/NodeGoat.git"


def main():
    ap = argparse.ArgumentParser(description="Software Supply Chain Guardian")
    ap.add_argument("repo_url", nargs="?", default=DEFAULT_REPO,
                    help="public GitHub repo URL (default: OWASP NodeGoat)")
    args = ap.parse_args()
    run_pipeline(args.repo_url)


if __name__ == "__main__":
    main()