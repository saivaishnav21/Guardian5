import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RunContext:
    """Shared state and evidence store for one Guardian run."""
    repo_url: str
    run_dir: Path
    state: dict = field(default_factory=dict)
    log: list = field(default_factory=list)

    @classmethod
    def create(cls, repo_url: str) -> "RunContext":
        run_id = time.strftime("%Y%m%d-%H%M%S")
        run_dir = Path("runs") / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        return cls(repo_url=repo_url, run_dir=run_dir)

    def note(self, agent: str, message: str):
        entry = {"agent": agent, "message": message}
        self.log.append(entry)
        print(f"  [{agent}] {message}")

    def save(self, name: str, data) -> Path:
        path = self.run_dir / name
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def add_finding(self, finding) -> None:
        self.state.setdefault("findings", []).append(finding.to_dict())