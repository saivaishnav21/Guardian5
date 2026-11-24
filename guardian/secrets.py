"""Read optional local API settings without exporting them to scan subprocesses."""

import os
from pathlib import Path


def _file_settings() -> dict:
    try:
        from dotenv import dotenv_values
    except ImportError:
        return {}
    return dotenv_values(Path(__file__).resolve().parents[1] / ".env")


def groq_key() -> str:
    value = os.environ.get("GROQ_API_KEY") or _file_settings().get("GROQ_API_KEY") or ""
    return value.strip() if value != "your-key-here" else ""


def groq_model() -> str:
    return os.environ.get("GROQ_MODEL") or _file_settings().get("GROQ_MODEL") or "openai/gpt-oss-20b"


def scanner_env() -> dict[str, str]:
    """Keep credentials out of tools processing third-party source trees."""
    return {key: value for key, value in os.environ.items()
            if not (key.upper().endswith(("_API_KEY", "_TOKEN"))
                    or key.upper() in {"CODEX_SESSION_ID", "GH_TOKEN", "GITHUB_TOKEN"})}
