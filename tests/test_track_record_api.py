"""Contract tests for the public track-record endpoints."""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import rockycrypt_modules  # noqa: E402
import rockycrypt_server  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(rockycrypt_server.app) as c:
        yield c


@pytest.fixture(autouse=True)
def clear_cache():
    rockycrypt_modules._track_record_cache.update({"at": 0.0, "report": None})


def test_track_record_is_public_and_shaped_for_the_frontend(client):
    body = client.get("/api/track-record").json()

    assert body["source"] == "track_record"
    assert set(body) >= {"coverage", "tiers", "directional_accuracy", "warnings"}
    assert set(body["tiers"]) == set(rockycrypt_modules.backtest.TIER_ORDER)
    assert body["warnings"], "the numbers must never be published without caveats"


def test_track_record_signals_is_public_and_capped(client):
    body = client.get("/api/track-record/signals?limit=9999").json()
    assert body["count"] == len(body["signals"]) <= 500


def test_backtest_requires_admin(client):
    assert client.get("/api/backtest").status_code in (401, 403)


def test_backtest_rejects_junk_horizons(client):
    rockycrypt_server.app.dependency_overrides[rockycrypt_server._require_admin] = lambda: {"admin": True}
    try:
        assert client.get("/api/backtest?horizons=abc").status_code == 400
        assert client.get("/api/backtest?horizons=9999").status_code == 400
    finally:
        rockycrypt_server.app.dependency_overrides.clear()
