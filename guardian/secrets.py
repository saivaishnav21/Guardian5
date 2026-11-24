"""Read optional local API settings without exporting them to scan subprocesses."""

import os
from pathlib import Path


def _file_settings() -> dict:
    settings = {}
    try:
        from dotenv import dotenv_values
    except ImportError:
        dotenv_values = None
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if dotenv_values is not None:
        settings.update(dotenv_values(env_path))
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            settings[name.strip()] = value
    return settings


def groq_key() -> str:
    value = os.environ.get("GROQ_API_KEY") or _file_settings().get("GROQ_API_KEY") or ""
    return value.strip() if value != "your-key-here" else ""


def groq_model() -> str:
    return os.environ.get("GROQ_MODEL") or _file_settings().get("GROQ_MODEL") or "openai/gpt-oss-20b"


def deepseek_key() -> str:
    value = (
        os.environ.get("DEEPSEEK_API_KEY")
        or _file_settings().get("DEEPSEEK_API_KEY")
        or ""
    )
    return value.strip()


def deepseek_model() -> str:
    return (
        os.environ.get("DEEPSEEK_MODEL")
        or _file_settings().get("DEEPSEEK_MODEL")
        or "deepseek-chat"
    )


def deepseek_base_url() -> str:
    value = (
        os.environ.get("DEEPSEEK_API_BASE")
        or _file_settings().get("DEEPSEEK_API_BASE")
        or "https://api.deepseek.com"
    )
    return value.rstrip("/")


def scanner_env() -> dict[str, str]:
    """Keep credentials out of tools processing third-party source trees."""
    return {key: value for key, value in os.environ.items()
            if not (key.upper().endswith(("_API_KEY", "_TOKEN"))
                    or key.upper() in {"CODEX_SESSION_ID", "GH_TOKEN", "GITHUB_TOKEN"})}
