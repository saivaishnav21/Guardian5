import shutil
import subprocess
from pathlib import Path


def generate_sbom(target_dir: str, out_path: str) -> str:
    """Generate a CycloneDX SBOM for a project directory using cdxgen."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    npx = shutil.which("npx")
    if not npx:
        raise RuntimeError("npx not found. Install Node.js 20 LTS first.")
    cmd = [npx, "--yes", "@cyclonedx/cdxgen", "-t", "js", "-o", str(out_path), str(target_dir)]
    print("  running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return str(out_path)