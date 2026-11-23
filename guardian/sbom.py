import shutil
import subprocess
from pathlib import Path


def generate_sbom(target_dir: str, out_path: str) -> str:
    """Generate a CycloneDX SBOM for a project directory using cdxgen."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    cdxgen = shutil.which("cdxgen")
    if not cdxgen:
        raise RuntimeError("cdxgen not found. Install it with npm install -g @cdxgen/cdxgen.")
    cmd = [cdxgen, "-o", str(out_path), str(target_dir)]
    print("  running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return str(out_path)
