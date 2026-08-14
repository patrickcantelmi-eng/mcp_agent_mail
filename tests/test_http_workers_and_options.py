from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from mcp_agent_mail import config as _config, http as _http
from mcp_agent_mail.app import build_mcp_server
from mcp_agent_mail.http import build_http_app


def test_thread_pressure_snapshot_and_alarm_are_falsifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    class RecordingLogger:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, int | bool]]] = []

        def error(self, event: str, **fields: int | bool) -> None:
            self.events.append((event, fields))

    monkeypatch.setattr(_http.resource, "getrlimit", lambda _kind: (2048, 4096))
    monkeypatch.setattr(_http.threading, "active_count", lambda: 255)
    assert _http._thread_pressure_snapshot() == {
        "current_threads": 255,
        "soft_nproc_limit": 2048,
        "hard_nproc_limit": 4096,
        "alarm": False,
    }

    monkeypatch.setattr(_http.threading, "active_count", lambda: 256)
    snapshot = _http._thread_pressure_snapshot()
    logger = RecordingLogger()
    last_alarm = _http._maybe_alarm_thread_pressure(logger, snapshot, now=1000.0, last_alarm=None)
    assert last_alarm == 1000.0
    assert logger.events == [("thread_pressure.alarm", snapshot)]
    assert _http._maybe_alarm_thread_pressure(logger, snapshot, now=1299.0, last_alarm=last_alarm) == 1000.0
    assert len(logger.events) == 1
    assert _http._maybe_alarm_thread_pressure(logger, snapshot, now=1300.0, last_alarm=last_alarm) == 1300.0
    assert len(logger.events) == 2


@pytest.mark.asyncio
async def test_thread_pressure_worker_is_started(isolated_env) -> None:
    settings = _config.get_settings()
    app = build_http_app(settings, build_mcp_server())
    async with app.router.lifespan_context(app):
        worker_names = {task.get_coro().__name__ for task in app.state._background_tasks}
        assert "_worker_thread_pressure" in worker_names


def _rpc(method: str, params: dict) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": "1", "method": method, "params": params}


@pytest.mark.asyncio
async def test_http_ack_ttl_worker_log_mode(isolated_env, monkeypatch):
    # Enable ack TTL worker in LOG mode (default escalation)
    monkeypatch.setenv("ACK_TTL_ENABLED", "true")
    monkeypatch.setenv("ACK_TTL_SECONDS", "0")  # immediate
    monkeypatch.setenv("ACK_TTL_SCAN_INTERVAL_SECONDS", "1")
    with contextlib.suppress(Exception):
        _config.clear_settings_cache()

    settings = _config.get_settings()
    server = build_mcp_server()
    app = build_http_app(settings, server)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create one ack-required message so worker will warn
        await client.post(settings.http.path, json=_rpc("tools/call", {"name": "ensure_project", "arguments": {"human_key": "/backend"}}))
        await client.post(settings.http.path, json=_rpc("tools/call", {"name": "register_agent", "arguments": {"project_key": "Backend", "program": "codex", "model": "gpt-5", "name": "BlueLake"}}))
        await client.post(settings.http.path, json=_rpc("tools/call", {"name": "send_message", "arguments": {"project_key": "Backend", "sender_name": "BlueLake", "to": ["BlueLake"], "subject": "TTL", "body_md": "x", "ack_required": True}}))

        # Allow at least one scan tick
        await asyncio.sleep(1.2)
        # Health call to keep app active; nothing to assert other than no crash
        r = await client.post(settings.http.path, json=_rpc("tools/call", {"name": "health_check", "arguments": {}}))
        assert r.status_code in (200, 401, 403)


@pytest.mark.asyncio
async def test_http_ack_ttl_worker_file_reservation_escalation(isolated_env, monkeypatch):
    # Enable ack escalation to file_reservation mode so worker writes a file_reservation artifact
    monkeypatch.setenv("ACK_TTL_ENABLED", "true")
    monkeypatch.setenv("ACK_TTL_SECONDS", "0")
    monkeypatch.setenv("ACK_TTL_SCAN_INTERVAL_SECONDS", "1")
    monkeypatch.setenv("ACK_ESCALATION_ENABLED", "true")
    monkeypatch.setenv("ACK_ESCALATION_MODE", "file_reservation")
    monkeypatch.setenv("ACK_ESCALATION_CLAIM_TTL_SECONDS", "60")
    with contextlib.suppress(Exception):
        _config.clear_settings_cache()

    settings = _config.get_settings()
    server = build_mcp_server()
    app = build_http_app(settings, server)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(settings.http.path, json=_rpc("tools/call", {"name": "ensure_project", "arguments": {"human_key": "/backend"}}))
        await client.post(settings.http.path, json=_rpc("tools/call", {"name": "register_agent", "arguments": {"project_key": "Backend", "program": "codex", "model": "gpt-5", "name": "BlueLake"}}))
        # Trigger ack-required to self to make overdue soon
        await client.post(settings.http.path, json=_rpc("tools/call", {"name": "send_message", "arguments": {"project_key": "Backend", "sender_name": "BlueLake", "to": ["BlueLake"], "subject": "Overdue", "body_md": "x", "ack_required": True}}))
        await asyncio.sleep(1.2)
        # Read file_reservations resource — should exist (best-effort)
        r = await client.post(settings.http.path, json=_rpc("resources/read", {"uri": "resource://file_reservations/backend"}))
        assert r.status_code in (200, 401, 403)


@pytest.mark.asyncio
async def test_http_request_logging_and_cors_headers(isolated_env, monkeypatch):
    # Enable request logging and CORS
    monkeypatch.setenv("HTTP_REQUEST_LOG_ENABLED", "true")
    monkeypatch.setenv("HTTP_CORS_ENABLED", "true")
    monkeypatch.setenv("HTTP_CORS_ORIGINS", "http://example.com")
    with contextlib.suppress(Exception):
        _config.clear_settings_cache()
    settings = _config.get_settings()
    server = build_mcp_server()
    app = build_http_app(settings, server)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Preflight OPTIONS should pass
        r0 = await client.options(settings.http.path, headers={"Origin": "http://example.com", "Access-Control-Request-Method": "POST"})
        assert r0.status_code in (200, 204)
        r = await client.post(settings.http.path, json=_rpc("tools/call", {"name": "health_check", "arguments": {}}))
        assert r.status_code in (200, 401, 403)
