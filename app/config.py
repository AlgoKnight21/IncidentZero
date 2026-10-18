"""Environment-based configuration. No secrets are hardcoded."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    falkordb_host: str = field(default_factory=lambda: os.environ.get("FALKORDB_HOST", "localhost"))
    falkordb_port: int = field(default_factory=lambda: _int("FALKORDB_PORT", 6379))
    falkordb_username: str | None = field(default_factory=lambda: os.environ.get("FALKORDB_USERNAME") or None)
    falkordb_password: str | None = field(default_factory=lambda: os.environ.get("FALKORDB_PASSWORD") or None)
    graph_prefix: str = field(default_factory=lambda: os.environ.get("INCIDENTZERO_GRAPH_PREFIX", "incidentzero_"))
    # Engine-visible data root. Evaluator-only ground truth lives in PROJECT_ROOT/evaluation and is never configured here.
    scenario_root: Path = field(default_factory=lambda: Path(os.environ.get(
        "INCIDENTZERO_SCENARIO_ROOT", str(PROJECT_ROOT / "data" / "scenarios"))))
    query_timeout_ms: int = field(default_factory=lambda: _int("INCIDENTZERO_QUERY_TIMEOUT_MS", 5000))
    result_limit: int = field(default_factory=lambda: _int("INCIDENTZERO_RESULT_LIMIT", 500))
    max_ingest_records: int = field(default_factory=lambda: _int("INCIDENTZERO_MAX_INGEST_RECORDS", 5000))
    max_hops: int = field(default_factory=lambda: _int("INCIDENTZERO_MAX_HOPS", 4))
    socket_timeout_s: int = field(default_factory=lambda: _int("INCIDENTZERO_SOCKET_TIMEOUT_S", 10))


def get_settings() -> Settings:
    return Settings()


FORBIDDEN_PATH_PARTS = {"evaluation"}


def assert_engine_readable(path: Path) -> Path:
    """Local demonstration safeguard: the engine must never read evaluator-only files.

    This is NOT a security boundary against someone with repository access; it prevents accidental use.
    """
    resolved = path.resolve()
    if any(part in FORBIDDEN_PATH_PARTS for part in resolved.relative_to(resolved.anchor).parts):
        raise PermissionError(f"engine may not read evaluator-only path: {resolved}")
    return resolved
