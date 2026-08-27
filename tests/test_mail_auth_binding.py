"""Red controls for fleet auth + sender binding (bd fba-restock-planner-xlhjj).

Every control that must FAIL (forged sender, anonymous caller, unclaimed token
overreach, strict-mode shared token) is paired with a matched positive control
proving the same path succeeds when the identity is legitimate — a suite that
passes by breaking everything cannot go green here.
"""

import contextlib

import pytest
from httpx import ASGITransport, AsyncClient

from mcp_agent_mail import config as _config
from mcp_agent_mail.app import build_mcp_server
from mcp_agent_mail.authz import Principal, TokenRegistry, evaluate_identity_claims
from mcp_agent_mail.http import build_http_app

PROJECT = "/data/projects/mail-auth-binding"


def _rpc(method: str, params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": "1", "method": method, "params": params}


def _auth_env(monkeypatch, tmp_path, **overrides) -> "_config.Settings":
    """Deployed-shape env: shared tokens + localhost unauth OFF + writer default role."""
    env = {
        "HTTP_BEARER_TOKEN": "fleet-primary-token",
        "HTTP_BEARER_TOKENS": "fleet-secondary-token",
        "HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED": "false",
        # The deployed .env must carry this: with localhost unauth off, RBAC's
        # default role (reader) would otherwise 403 every write tool.
        "HTTP_RBAC_DEFAULT_ROLE": "writer",
        "MAIL_AGENT_TOKENS_PATH": str(tmp_path / "agent_tokens.json"),
    }
    env.update(overrides)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with contextlib.suppress(Exception):
        _config.clear_settings_cache()
    return _config.get_settings()


def _build(settings):
    return build_http_app(settings, build_mcp_server())


async def _call(client, settings, tool: str, args: dict, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return await client.post(
        settings.http.path,
        headers=headers,
        json=_rpc("tools/call", {"name": tool, "arguments": args}),
    )


def _structured(resp) -> dict:
    return resp.json().get("result", {}).get("structuredContent", {}) or {}


async def _bootstrap_agents(client, settings, token: str, names: list[str]) -> None:
    r = await _call(client, settings, "ensure_project", {"human_key": PROJECT}, token)
    assert r.status_code == 200, r.text
    for name in names:
        r = await _call(
            client,
            settings,
            "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test", "name": name},
            token,
        )
        assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_anonymous_and_wrong_token_refused(isolated_env, tmp_path, monkeypatch):
    settings = _auth_env(monkeypatch, tmp_path)
    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await _call(client, settings, "health_check", {}, None)
        assert r.status_code == 401
        r = await _call(client, settings, "health_check", {}, "deadbeef-wrong")
        assert r.status_code == 401
        # matched positive control: the primary shared token is admitted
        r = await _call(client, settings, "health_check", {}, "fleet-primary-token")
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_dual_accept_secondary_token_and_unattested_stamp(isolated_env, tmp_path, monkeypatch):
    settings = _auth_env(monkeypatch, tmp_path)
    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _bootstrap_agents(client, settings, "fleet-secondary-token", ["BlueLake", "RedStone"])
        # legacy window: shared token may still assert any sender ...
        r = await _call(
            client,
            settings,
            "send_message",
            {
                "project_key": PROJECT,
                "sender_name": "BlueLake",
                "to": ["RedStone"],
                "subject": "legacy window",
                "body_md": "sent via shared token",
            },
            "fleet-secondary-token",
        )
        assert r.status_code == 200, r.text
        # ... but the message is stamped UNattested — the honest dual-accept marker.
        r = await _call(
            client,
            settings,
            "fetch_inbox",
            {"project_key": PROJECT, "agent_name": "RedStone"},
            "fleet-primary-token",
        )
        assert r.status_code == 200, r.text
        items = _structured(r).get("result", [])
        assert items and items[0]["sender_attested"] is False


@pytest.mark.asyncio
async def test_bound_token_forged_sender_refused_with_matched_control(isolated_env, tmp_path, monkeypatch):
    settings = _auth_env(monkeypatch, tmp_path)
    registry = TokenRegistry(tmp_path / "agent_tokens.json")
    blue_token, _ = registry.mint(agent_name="BlueLake")
    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _bootstrap_agents(client, settings, "fleet-primary-token", ["BlueLake", "RedStone"])

        # RED CONTROL: bound credential forging another sender is REJECTED.
        r = await _call(
            client,
            settings,
            "send_message",
            {
                "project_key": PROJECT,
                "sender_name": "RedStone",
                "to": ["BlueLake"],
                "subject": "forged",
                "body_md": "I claim to be RedStone",
            },
            blue_token,
        )
        assert r.status_code == 403
        assert r.json().get("error") == "sender_binding_refused"

        # Bound credential may not read another agent's inbox either.
        r = await _call(
            client,
            settings,
            "fetch_inbox",
            {"project_key": PROJECT, "agent_name": "RedStone"},
            blue_token,
        )
        assert r.status_code == 403

        # MATCHED CONTROL: the same credential sending as its own identity succeeds
        # and the message is server-attested.
        r = await _call(
            client,
            settings,
            "send_message",
            {
                "project_key": PROJECT,
                "sender_name": "BlueLake",
                "to": ["RedStone"],
                "subject": "genuine",
                "body_md": "sent with my own bound token",
            },
            blue_token,
        )
        assert r.status_code == 200, r.text
        r = await _call(
            client,
            settings,
            "fetch_inbox",
            {"project_key": PROJECT, "agent_name": "RedStone"},
            "fleet-primary-token",
        )
        items = _structured(r).get("result", [])
        assert items and items[0]["sender_attested"] is True


@pytest.mark.asyncio
async def test_unclaimed_token_claims_at_register_and_nothing_else(isolated_env, tmp_path, monkeypatch):
    settings = _auth_env(monkeypatch, tmp_path)
    registry = TokenRegistry(tmp_path / "agent_tokens.json")
    lane_token, lane_sha = registry.mint()  # unclaimed launcher token
    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _bootstrap_agents(client, settings, "fleet-primary-token", ["RedStone"])

        # RED CONTROL: unclaimed token may not send.
        r = await _call(
            client,
            settings,
            "send_message",
            {
                "project_key": PROJECT,
                "sender_name": "RedStone",
                "to": ["RedStone"],
                "subject": "x",
                "body_md": "x",
            },
            lane_token,
        )
        assert r.status_code == 403

        # register_agent claims the token (TOFU) with a server-generated name.
        r = await _call(
            client,
            settings,
            "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test"},
            lane_token,
        )
        assert r.status_code == 200, r.text
        claimed_name = _structured(r).get("name")
        assert claimed_name
        entry = registry.lookup_sha(lane_sha)
        assert entry and entry["agent_name"] == claimed_name

        # Now bound: sending as the claimed identity works and is attested ...
        r = await _call(
            client,
            settings,
            "send_message",
            {
                "project_key": PROJECT,
                "sender_name": claimed_name,
                "to": ["RedStone"],
                "subject": "claimed",
                "body_md": "bound after claim",
            },
            lane_token,
        )
        assert r.status_code == 200, r.text

        # ... and re-registering under a DIFFERENT explicit name is refused.
        r = await _call(
            client,
            settings,
            "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test", "name": "GreenCastle"},
            lane_token,
        )
        assert r.status_code == 403

        # Bound token + omitted name re-registers its own identity (seat continuity).
        r = await _call(
            client,
            settings,
            "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test"},
            lane_token,
        )
        assert r.status_code == 200
        assert _structured(r).get("name") == claimed_name


@pytest.mark.asyncio
async def test_unclaimed_token_expires_after_ttl(isolated_env, tmp_path, monkeypatch):
    # bd u5yak (ii): an unclaimed token minted long ago must stop authenticating
    # and must not be claimable — bound tokens are unaffected.
    settings = _auth_env(monkeypatch, tmp_path, MAIL_AGENT_UNCLAIMED_TOKEN_TTL_SECONDS="1800")
    registry = TokenRegistry(tmp_path / "agent_tokens.json")
    stale_token, stale_sha = registry.mint()          # unclaimed, will be aged out
    fresh_token, _ = registry.mint()                   # unclaimed, recent
    bound_token, _ = registry.mint(agent_name="BlueLake")

    # Backdate the stale entry's created_ts past the TTL, directly in the file.
    import json
    from datetime import datetime, timedelta, timezone
    reg_path = tmp_path / "agent_tokens.json"
    data = json.loads(reg_path.read_text())
    data["tokens"][stale_sha]["created_ts"] = (
        datetime.now(timezone.utc) - timedelta(seconds=3600)
    ).isoformat()
    reg_path.write_text(json.dumps(data))

    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _bootstrap_agents(client, settings, "fleet-primary-token", ["RedStone"])

        # RED CONTROL: the aged-out unclaimed token no longer authenticates ...
        r = await _call(client, settings, "health_check", {}, stale_token)
        assert r.status_code == 401
        # ... and cannot be used to claim an identity.
        r = await _call(
            client, settings, "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test"}, stale_token,
        )
        assert r.status_code == 401

        # MATCHED CONTROLS: a recent unclaimed token still claims, and a bound
        # token is never expired by the unclaimed TTL.
        r = await _call(
            client, settings, "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test"}, fresh_token,
        )
        assert r.status_code == 200, r.text
        r = await _call(client, settings, "health_check", {}, bound_token)
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_strict_mode_refuses_shared_token_identity_tools(isolated_env, tmp_path, monkeypatch):
    settings = _auth_env(monkeypatch, tmp_path, MAIL_SENDER_BINDING="strict")
    registry = TokenRegistry(tmp_path / "agent_tokens.json")
    blue_token, _ = registry.mint(agent_name="BlueLake")
    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Non-identity tools still work for shared tokens in strict mode.
        r = await _call(client, settings, "ensure_project", {"human_key": PROJECT}, "fleet-primary-token")
        assert r.status_code == 200, r.text
        # RED CONTROL: identity-asserting tools are closed to shared tokens.
        r = await _call(
            client,
            settings,
            "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test", "name": "BlueLake"},
            "fleet-primary-token",
        )
        assert r.status_code == 403
        # MATCHED CONTROL: a bound per-agent token still passes in strict mode.
        r = await _call(
            client,
            settings,
            "register_agent",
            {"project_key": PROJECT, "program": "test", "model": "test"},
            blue_token,
        )
        assert r.status_code == 200, r.text
        assert _structured(r).get("name") == "BlueLake"


@pytest.mark.asyncio
async def test_revoked_token_fails_closed(isolated_env, tmp_path, monkeypatch):
    settings = _auth_env(monkeypatch, tmp_path)
    registry = TokenRegistry(tmp_path / "agent_tokens.json")
    blue_token, blue_sha = registry.mint(agent_name="BlueLake")
    registry.revoke(sha_prefix=blue_sha[:12])
    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await _call(client, settings, "health_check", {}, blue_token)
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_upstream_default_localhost_dev_still_open(isolated_env, tmp_path, monkeypatch):
    """Upstream compatibility: bearer token + allow_localhost default keeps localhost open."""
    settings = _auth_env(monkeypatch, tmp_path, HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED="true")
    app = _build(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await _call(client, settings, "health_check", {}, None)
        assert r.status_code == 200


def test_evaluate_identity_claims_unit():
    bound = Principal(kind="agent", agent_name="BlueLake", token_sha256="x")
    shared = Principal(kind="shared")
    unclaimed = Principal(kind="unclaimed", token_sha256="y")

    assert evaluate_identity_claims(bound, "send_message", {"sender_name": "BlueLake"}, strict=False) is None
    assert evaluate_identity_claims(bound, "send_message", {"sender_name": "bluelake"}, strict=False) is None
    assert evaluate_identity_claims(bound, "send_message", {"sender_name": "RedStone"}, strict=False)
    assert evaluate_identity_claims(bound, "whois", {"agent_name": "RedStone"}, strict=False) is None
    assert evaluate_identity_claims(shared, "send_message", {"sender_name": "RedStone"}, strict=False) is None
    assert evaluate_identity_claims(shared, "send_message", {"sender_name": "RedStone"}, strict=True)
    assert evaluate_identity_claims(unclaimed, "register_agent", {"name": "Any"}, strict=False) is None
    assert evaluate_identity_claims(unclaimed, "send_message", {"sender_name": "Any"}, strict=False)
