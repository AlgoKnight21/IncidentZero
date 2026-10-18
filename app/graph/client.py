"""FalkorDB connection handling (falkordb-py >= 1.8).

Verified against falkordb-py 1.8.0 source: FalkorDB(host, port, username, password, socket_timeout, ...),
FalkorDB.select_graph(name) -> Graph, Graph.query(q, params=None, timeout=None) / Graph.ro_query(...),
QueryResult.result_set / .header / .nodes_created / .relationships_created / .properties_set,
FalkorDB.list_graphs(), Graph.delete(), Graph.create_node_range_index(label, *props), Graph.list_indices().

There is deliberately NO fallback: if FalkorDB is unreachable, GraphUnavailableError is raised and the
investigation fails with a dependency error instead of returning results from another store.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from app.config import Settings, get_settings

log = logging.getLogger("incidentzero.graph")

_GRAPH_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,96}$")


class GraphUnavailableError(RuntimeError):
    """FalkorDB could not be reached; graph-dependent work cannot proceed."""


class GraphQueryError(RuntimeError):
    """FalkorDB rejected or failed a query."""


def _is_connection_error(exc: BaseException) -> bool:
    try:
        from redis.exceptions import ConnectionError as RConnErr, TimeoutError as RTimeout
    except ImportError:  # pragma: no cover
        RConnErr = RTimeout = ()  # type: ignore
    return isinstance(exc, (RConnErr, RTimeout, ConnectionError, TimeoutError, OSError))


class GraphClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._db = None

    def _connect(self):
        if self._db is not None:
            return self._db
        try:
            from falkordb import FalkorDB  # official client
        except ImportError as exc:  # pragma: no cover - dependency problem
            raise GraphUnavailableError("falkordb python client is not installed") from exc
        s = self.settings
        try:
            db = FalkorDB(host=s.falkordb_host, port=s.falkordb_port, username=s.falkordb_username,
                          password=s.falkordb_password, socket_timeout=s.socket_timeout_s,
                          socket_connect_timeout=3)
            db.connection.ping()
        except Exception as exc:
            raise GraphUnavailableError(
                f"FalkorDB unreachable at {s.falkordb_host}:{s.falkordb_port}: {type(exc).__name__}: {exc}") from exc
        self._db = db
        return db

    def graph_name(self, scenario_id: str) -> str:
        name = f"{self.settings.graph_prefix}{scenario_id}"
        if not _GRAPH_NAME_RE.match(name):
            raise ValueError(f"invalid graph name {name!r}")
        return name

    def graph(self, scenario_id: str):
        return self._connect().select_graph(self.graph_name(scenario_id))

    def ping(self) -> dict[str, Any]:
        db = self._connect()
        try:
            info = db.connection.execute_command("MODULE", "LIST")
        except Exception as exc:
            self._db = None
            raise GraphUnavailableError(f"FalkorDB ping failed: {exc}") from exc
        modules = []
        for m in info or []:
            d = {}
            if isinstance(m, (list, tuple)):
                it = iter(m)
                for k, v in zip(it, it):
                    k = k.decode() if isinstance(k, bytes) else k
                    v = v.decode() if isinstance(v, bytes) else v
                    d[k] = v
            elif isinstance(m, dict):
                d = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                     for k, v in m.items()}
            modules.append(d)
        return {"modules": modules}

    def guarded(self, fn, *args, **kwargs):
        """Call a falkordb-py function, mapping connection failures to GraphUnavailableError."""
        try:
            return fn(*args, **kwargs)
        except GraphUnavailableError:
            raise
        except Exception as exc:
            if _is_connection_error(exc):
                self._db = None
                raise GraphUnavailableError(f"FalkorDB connection failed: {exc}") from exc
            raise

    def list_graphs(self) -> list[str]:
        return list(self.guarded(lambda: self._connect().list_graphs()))

    def run(self, scenario_id: str, query: str, params: dict[str, Any] | None = None, *, read_only: bool = True):
        """Execute a parameterised Cypher query with the configured timeout. Returns QueryResult."""
        g = self.graph(scenario_id)
        timeout = self.settings.query_timeout_ms
        try:
            if read_only:
                return g.ro_query(query, params=params or {}, timeout=timeout)
            return g.query(query, params=params or {}, timeout=timeout)
        except GraphUnavailableError:
            raise
        except Exception as exc:
            if _is_connection_error(exc):
                self._db = None
                raise GraphUnavailableError(f"FalkorDB connection failed during query: {exc}") from exc
            raise GraphQueryError(f"{type(exc).__name__}: {exc}") from exc

    def rows(self, scenario_id: str, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        res = self.run(scenario_id, query, params, read_only=True)
        header = [h[1] if isinstance(h, (list, tuple)) else h for h in res.header]
        header = [h.decode() if isinstance(h, bytes) else h for h in header]
        return [dict(zip(header, r)) for r in res.result_set]

    def delete_graph(self, scenario_id: str) -> bool:
        name = self.graph_name(scenario_id)
        if name not in self.list_graphs():
            return False
        self.guarded(lambda: self.graph(scenario_id).delete())
        return True
