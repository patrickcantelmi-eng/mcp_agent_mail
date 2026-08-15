from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

from mcp_agent_mail.config import clear_settings_cache, get_settings
from mcp_agent_mail.db import ensure_schema, get_engine, reset_database_state
from mcp_agent_mail.utils import sanitize_agent_name, slugify


@pytest.mark.asyncio
async def test_aiosqlite_cancelled_queries_reclaim_worker_threads(tmp_path: Path) -> None:
    import aiosqlite
    from sqlalchemy import text
    from sqlalchemy.dialects.sqlite.aiosqlite import AsyncAdapt_aiosqlite_connection, SQLiteDialect_aiosqlite
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

    assert SQLiteDialect_aiosqlite.has_terminate
    assert callable(getattr(AsyncAdapt_aiosqlite_connection, "terminate", None))
    assert callable(getattr(aiosqlite.Connection, "stop", None))

    async def hold_connection(target_engine: AsyncEngine) -> None:
        async with target_engine.connect() as connection:
            await connection.execute(
                text(
                    "WITH RECURSIVE c(x) AS "
                    "(SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 3000000) "
                    "SELECT count(*) FROM c"
                )
            )

    baseline_threads = threading.active_count()
    for round_number in range(10):
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / f'probe-{round_number}.db'}")
        task = asyncio.create_task(hold_connection(engine))
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        finally:
            await engine.dispose()

    await asyncio.sleep(1.5)
    residual_threads = threading.active_count() - baseline_threads
    assert residual_threads <= 1, f"{residual_threads} SQLite worker threads survived cancellation"


def test_slugify_and_sanitize_edges():
    assert slugify("  Hello World!!  ") == "hello-world"
    assert slugify("") == "project"
    assert sanitize_agent_name(" A!@#$ ") == "A"
    assert sanitize_agent_name("!!!") is None


def test_config_csv_and_bool_parsing(monkeypatch):
    monkeypatch.setenv("HTTP_RBAC_READER_ROLES", "reader, ro ,, read ")
    monkeypatch.setenv("HTTP_RATE_LIMIT_ENABLED", "true")
    clear_settings_cache()
    s = get_settings()
    assert {"reader", "ro", "read"}.issubset(set(s.http.rbac_reader_roles))
    assert s.http.rate_limit_enabled is True


def test_db_engine_reset_and_reinit(isolated_env):
    # Reset and ensure engine can be re-initialized and schema ensured
    reset_database_state()
    # Access engine should lazy-init
    _ = get_engine()
    # Ensure schema executes without error
    asyncio.run(ensure_schema())
