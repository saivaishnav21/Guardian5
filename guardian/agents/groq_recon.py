"""Optional filename-only suggestions for manifests unknown to deterministic recon."""

import json
import os
import re
from pathlib import Path

DEFAULT_MODEL = "openai/gpt-oss-20b"
ECOSYSTEM_RE = re.compile(r"^[a-z][a-z0-9_+.-]{0,39}$")
MAX_SUGGESTIONS = 20


def suggest_manifests(paths: list[str]) -> dict:
    """Suggest, but do not verify, package manifests from repository-relative paths."""
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
    except ImportError:
        pass
    model = os.getenv("GROQ_MODEL") or DEFAULT_MODEL
    result = {"status": "skipped_no_key", "model": model, "suggestions": []}
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return result
    if not paths:
        result["status"] = "skipped_no_candidates"
        return result

    try:
        from groq import Groq

        client = Groq(api_key=api_key, timeout=20.0, max_retries=0)
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Identify package-manager manifest and lockfile names from a list of "
                        "repository-relative paths. You only know filenames, not file contents. "
                        "Return JSON with a suggestions array. Each suggestion must have "
                        "path, ecosystem, kind (manifest or lockfile), and reason. "
                        "Use exact paths from the input. Omit uncertain files and ordinary "
                        "application configuration. Do not invent dependencies or versions."
                    ),
                },
                {"role": "user", "content": json.dumps({"paths": paths})},
            ],
            response_format={"type": "json_object"},
            max_completion_tokens=1200,
        )
        content = completion.choices[0].message.content
        payload = json.loads(content or "{}")
        raw_suggestions = payload.get("suggestions", []) if isinstance(payload, dict) else []
        if not isinstance(raw_suggestions, list):
            raw_suggestions = []

        allowed_paths = set(paths)
        seen = set()
        suggestions = []
        for item in raw_suggestions:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            ecosystem = item.get("ecosystem")
            kind = item.get("kind")
            reason = item.get("reason")
            if (not isinstance(path, str) or path not in allowed_paths or path in seen
                    or not isinstance(ecosystem, str) or not ECOSYSTEM_RE.fullmatch(ecosystem)
                    or kind not in {"manifest", "lockfile"} or not isinstance(reason, str)):
                continue
            suggestions.append({
                "path": path,
                "ecosystem": ecosystem,
                "kind": kind,
                "reason": reason[:200],
                "verified": False,
            })
            seen.add(path)
            if len(suggestions) == MAX_SUGGESTIONS:
                break
        result["status"] = "completed"
        result["suggestions"] = suggestions
    except Exception as exc:
        # The optional service must not stop the deterministic scan or expose secrets in logs.
        result["status"] = "error"
        result["error_type"] = type(exc).__name__
    return result
