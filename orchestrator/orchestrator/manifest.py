from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import yaml


class ManifestError(Exception):
    """Raised for any manifest-load failure: missing file, bad YAML, missing
    required field. Wrapping these in a project-defined exception lets callers
    tell "user gave us a bad manifest" apart from a real bug, and produces a
    one-line error instead of a Python traceback that points at yaml internals.
    """


def _format_yaml_location(path: str | Path, exc: yaml.YAMLError) -> str:
    """Extract ``path:line:col`` from a YAML error if PyYAML attached a mark.

    PyYAML's MarkedYAMLError exposes ``problem_mark`` with 0-indexed line and
    column. We render them 1-indexed to match what every editor and the
    ``agentctl`` validator already use.
    """
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    if mark is None:
        return f"{path}"
    return f"{path}:{mark.line + 1}:{mark.column + 1}"


_PROVIDER_BASE_URLS: dict[str, str] = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com/v1",
    "cisco": "https://llm-proxy.dev.outshift.ai/",
    "outshift": "https://llm-proxy.dev.outshift.ai/",
}

_PROVIDER_API_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "cisco": "OPENAI_API_KEY",
    "outshift": "OPENAI_API_KEY",
    "azure": "OPENAI_API_KEY",
}


@dataclass
class AgentManifest:
    name: str
    command: list[str]
    allowed_hosts: list[str]           # required; [] = deny all egress
    allowed_paths: list[str]           # required; [] until P1 ships path enforcement
    env: dict[str, str] = field(default_factory=dict)
    mode: str = "enforce"              # "enforce" | "audit"
    allowed_bins: list[str] = field(default_factory=list)
    forbidden_caps: list[str] = field(default_factory=list)
    working_dir: str | None = None
    model: str | None = None           # e.g. "claude-sonnet-4-6", "gpt-4o", "azure/gpt-5.4"
    provider: str | None = None        # "anthropic" | "openai" | "azure" | "cisco" | "outshift"
    base_url: str | None = None        # explicit override; derived from provider if omitted

    def resolved_base_url(self) -> str | None:
        if self.base_url:
            return self.base_url
        if self.provider:
            return _PROVIDER_BASE_URLS.get(self.provider.lower())
        return None

    def missing_provider_hosts(self) -> list[str]:
        """Return provider hostnames implied by provider/base_url but absent from allowed_hosts."""
        from urllib.parse import urlparse
        base_url = self.resolved_base_url()
        if not base_url:
            return []
        host = urlparse(base_url).hostname or ""
        if not host:
            return []
        if host in self.allowed_hosts:
            return []
        return [host]

    def model_env_vars(self) -> dict[str, str]:
        """Return env vars to inject so agent code can read MODEL/API_BASE_URL/API_KEY."""
        import os
        vars: dict[str, str] = {}
        if self.model:
            vars["MODEL"] = self.model
        if self.provider:
            vars["PROVIDER"] = self.provider
        base_url = self.resolved_base_url()
        if base_url:
            vars["API_BASE_URL"] = base_url
        provider_key = _PROVIDER_API_KEY_ENV.get((self.provider or "").lower())
        if provider_key:
            api_key = os.environ.get(provider_key) or os.environ.get("API_KEY")
            if api_key:
                vars["API_KEY"] = api_key
        return vars


_REQUIRED = ("name", "command", "allowed_hosts", "allowed_paths")


def load_manifest(path: str | Path) -> AgentManifest:
    # encoding="utf-8" is explicit because the runtime's default is locale-
    # dependent — a CI host with LANG=C falls back to ASCII and crashes on
    # any non-ASCII byte in the manifest.
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise ManifestError(f"manifest '{path}' not found") from e
    except PermissionError as e:
        raise ManifestError(f"manifest '{path}' not readable: {e}") from e
    except OSError as e:
        raise ManifestError(f"manifest '{path}' could not be read: {e}") from e
    except yaml.YAMLError as e:
        problem = getattr(e, "problem", None) or str(e)
        raise ManifestError(
            f"{_format_yaml_location(path, e)}: invalid YAML: {problem}"
        ) from e

    if data is None:
        raise ManifestError(f"manifest '{path}' is empty")
    if not isinstance(data, dict):
        raise ManifestError(
            f"manifest '{path}' must be a YAML mapping at the top level; got {type(data).__name__}"
        )
    for key in _REQUIRED:
        if key not in data:
            raise ManifestError(
                f"Manifest '{path}' is missing required field '{key}'. "
                f"Use an empty list ([]) to explicitly allow nothing."
            )
    cmd = data["command"]
    return AgentManifest(
        name=data["name"],
        command=cmd if isinstance(cmd, list) else cmd.split(),
        allowed_hosts=data["allowed_hosts"],
        allowed_paths=data["allowed_paths"],
        env=data.get("env", {}),
        mode=data.get("mode", "enforce"),
        allowed_bins=data.get("allowed_bins", []),
        forbidden_caps=data.get("forbidden_caps", []),
        working_dir=data.get("working_dir"),
        model=data.get("model"),
        provider=data.get("provider"),
        base_url=data.get("base_url"),
    )
