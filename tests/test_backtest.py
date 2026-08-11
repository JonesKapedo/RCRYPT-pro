"""Tests for the signal backtester and track record."""

import json
import math
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backtest


def make_history(prices, symbol="TEST", start="2026-01-01"):
    """Build a history dict from a list of closing prices, one per session."""
    d0 = date.fromisoformat(start)
    rows = [
        {
            "date": (d0 + timedelta(days=i)).isoformat(),
            "open": p,
            "high": p * 1.01,
            "low": p * 0.99,
            "close": p,
            "volume": 1000 + i,
            "change_pct": 0.0,
        }
        for i, p in enumerate(prices)
    ]
    return {symbol: rows}


class StubEngine:
    """Deterministic engine: always emits the tier it was constructed with."""

    def __init__(self, signal="BUY", score=50):
        self.signal, self.score = signal, score

    def score_full(self, indicators):
        return {"score": self.score, "signal": self.signal, "reasons": []}


class StubAnalyzer:
    def analyze(self, df):
        return {"price": float(df["Close"].iloc[-1]), "data_days": len(df)}


# ─── Frame construction ───────────────────────────────────────────────────────

def test_frame_from_rows_sorts_dedupes_and_drops_bad_rows():
    rows = [
        {"date": "2026-01-03", "close": 12, "open": 12, "high": 12, "low": 12, "volume": 1},
        {"date": "2026-01-01", "close": 10, "open": 10, "high": 10, "low": 10, "volume": 1},
        {"date": "2026-01-03", "close": 13, "open": 13, "high": 13, "low": 13, "volume": 1},
        {"date": "2026-01-02", "close": 0, "open": 0, "high": 0, "low": 0, "volume": 1},
    ]
    df = backtest.frame_from_rows(rows)
    assert list(df["Close"]) == [10.0, 13.0]           # sorted, last duplicate wins, zero dropped


def test_frame_from_rows_handles_empty_and_malformed():
    assert backtest.frame_from_rows([]).empty
    assert backtest.frame_from_rows([{"nope": 1}]).empty


# ─── No lookahead ─────────────────────────────────────────────────────────────

def test_observations_use_only_past_data():
    """The analyzer must never see a row dated after the day being scored."""
    seen_lengths = []

    class SpyAnalyzer(StubAnalyzer):
        def analyze(self, df):
            seen_lengths.append(len(df))
            return super().analyze(df)

    prices = [10 + i for i in range(30)]
    df = backtest.frame_from_rows(make_history(prices)["TEST"])
    backtest.observations_for_symbol("TEST", df, SpyAnalyzer(), StubEngine(), (5,), min_history=20)

    assert seen_lengths == list(range(20, 31))


def test_forward_return_is_measured_correctly():
    prices = [100.0] * 20 + [110.0]           # +10% on the session after day 19
    df = backtest.frame_from_rows(make_history(prices)["TEST"])
    obs = backtest.observations_for_symbol("TEST", df, StubAnalyzer(), StubEngine(), (1,), min_history=20)

    assert obs[0].date == "2026-01-20"
    assert obs[0].forward_returns[1] == pytest.approx(10.0)


def test_forward_return_is_none_past_the_end_of_history():
    prices = [100.0] * 21
    df = backtest.frame_from_rows(make_history(prices)["TEST"])
    obs = backtest.observations_for_symbol("TEST", df, StubAnalyzer(), StubEngine(), (60,), min_history=20)

    assert all(o.forward_returns[60] is None for o in obs)


def test_symbols_below_min_history_are_skipped():
    df = backtest.frame_from_rows(make_history([100.0] * 10)["TEST"])
    assert backtest.observations_for_symbol("TEST", df, StubAnalyzer(), StubEngine(), (5,), 20) == []


# ─── Aggregation ──────────────────────────────────────────────────────────────

def _obs(signal, returns, horizon=5):
    return [
        backtest.Observation(
            date=f"2026-01-{i + 1:02d}", symbol="TEST", score=50, signal=signal,
            price=100.0, forward_returns={horizon: r}, excess_returns={horizon: r - 1.0},
        )
        for i, r in enumerate(returns)
    ]


def test_bullish_hit_rate_counts_gains():
    stats = backtest.summarize_tier(_obs("BUY", [5.0, -2.0, 3.0, 1.0]), "BUY", 5)
    assert stats.n == 4
    assert stats.hit_rate == 75.0
    assert stats.avg_return == pytest.approx(1.75)
    assert stats.best == 5.0 and stats.worst == -2.0


def test_bearish_hit_rate_counts_declines():
    """A SELL that is followed by a fall is a hit — the naive 'return > 0' rule
    would score the engine's best bearish calls as failures."""
    stats = backtest.summarize_tier(_obs("SELL", [-5.0, -3.0, 2.0, -1.0]), "SELL", 5)
    assert stats.hit_rate == 75.0


def test_neutral_hit_rate_rewards_staying_put():
    stats = backtest.summarize_tier(_obs("NEUTRAL", [0.5, -1.0, 9.0, -8.0]), "NEUTRAL", 5)
    assert stats.hit_rate == 50.0


def test_excess_return_is_relative_to_the_market():
    stats = backtest.summarize_tier(_obs("BUY", [5.0, 3.0]), "BUY", 5)
    assert stats.avg_return == pytest.approx(4.0)
    assert stats.avg_excess_return == pytest.approx(3.0)


def test_empty_tier_reports_zero_not_a_crash():
    stats = backtest.summarize_tier([], "STRONG BUY", 5)
    assert stats.n == 0 and stats.hit_rate is None and stats.max_drawdown is None


def test_max_drawdown_is_negative_when_the_curve_falls():
    dd = backtest.summarize_tier(_obs("BUY", [10.0, -20.0, -10.0]), "BUY", 5).max_drawdown
    assert dd is not None and dd < -25.0


# ─── Benchmark ────────────────────────────────────────────────────────────────

def test_benchmark_averages_every_symbol_on_the_same_date():
    frames = {
        "A": backtest.frame_from_rows(make_history([100.0, 110.0])["TEST"]),
        "B": backtest.frame_from_rows(make_history([100.0, 90.0])["TEST"]),
    }
    market = backtest._market_returns(frames, (1,))
    assert market["2026-01-01"][1] == pytest.approx(0.0)      # +10% and -10%


# ─── End-to-end backtest ──────────────────────────────────────────────────────

def test_run_backtest_reports_coverage_and_tiers():
    history = make_history([100.0 + i for i in range(40)], symbol="RISER")
    report = backtest.run_backtest(
        history=history, horizons=(5,), min_history=20,
        analyzer=StubAnalyzer(), engine=StubEngine("BUY"),
    )

    assert report["coverage"]["symbols"] == 1
    assert report["coverage"]["observations"] == 21          # rows 19..39
    buy = report["tiers"]["BUY"]["5"]
    assert buy["n"] == 16                                    # last 5 have no forward price
    assert buy["hit_rate"] == 100.0                          # monotonic riser
    assert report["directional_accuracy"]["5"]["accuracy"] == 100.0


def test_run_backtest_on_empty_history_warns_instead_of_crashing():
    report = backtest.run_backtest(
        history={}, horizons=(5,), analyzer=StubAnalyzer(), engine=StubEngine(),
    )
    assert report["coverage"]["observations"] == 0
    assert any("No price history" in w for w in report["warnings"])


def test_shallow_history_produces_a_loud_warning():
    report = backtest.run_backtest(
        history=make_history([100.0] * 5), horizons=(5,),
        analyzer=StubAnalyzer(), engine=StubEngine(),
    )
    assert any("fewer than" in w for w in report["warnings"])


# ─── Track record ─────────────────────────────────────────────────────────────

def test_record_signals_appends_and_is_idempotent(tmp_path):
    log = tmp_path / "signal_log.json"
    results = [{"symbol": "SCOM", "signal": "BUY", "score": 40, "price": 35.5, "data_days": 30}]

    assert backtest.record_signals(results, "2026-01-05", log) == 1
    assert backtest.record_signals(results, "2026-01-05", log) == 0     # same day again
    assert backtest.record_signals(results, "2026-01-06", log) == 1

    entries = json.loads(log.read_text())
    assert [e["date"] for e in entries] == ["2026-01-05", "2026-01-06"]


def test_record_signals_never_rewrites_history(tmp_path):
    """A re-run with a different call for a day already logged must not edit it."""
    log = tmp_path / "signal_log.json"
    backtest.record_signals([{"symbol": "SCOM", "signal": "BUY", "score": 40, "price": 35.5}], "2026-01-05", log)
    backtest.record_signals([{"symbol": "SCOM", "signal": "STRONG SELL", "score": -80, "price": 35.5}], "2026-01-05", log)

    entries = json.loads(log.read_text())
    assert len(entries) == 1 and entries[0]["signal"] == "BUY"


def test_record_signals_skips_incomplete_rows(tmp_path):
    log = tmp_path / "signal_log.json"
    assert backtest.record_signals([{"symbol": "SCOM"}, {"signal": "BUY", "price": 1}], "2026-01-05", log) == 0


def test_evaluate_track_record_scores_emitted_signals(tmp_path):
    log = tmp_path / "signal_log.json"
    history = make_history([100.0, 100.0, 100.0, 100.0, 100.0, 105.0], symbol="TEST")
    hist_file = tmp_path / "price_history.json"
    hist_file.write_text(json.dumps(history))

    backtest.record_signals(
        [{"symbol": "TEST", "signal": "BUY", "score": 30, "price": 100.0}], "2026-01-01", log,
    )
    report = backtest.evaluate_track_record(horizons=(5,), log_path=log, history_path=hist_file)

    assert report["evaluated_signals"] == 1
    assert report["tiers"]["BUY"]["5"]["avg_return"] == pytest.approx(5.0)


def test_recent_signals_attaches_outcomes(tmp_path):
    log = tmp_path / "signal_log.json"
    hist_file = tmp_path / "price_history.json"
    hist_file.write_text(json.dumps(make_history([100.0, 110.0], symbol="TEST")))
    backtest.record_signals([{"symbol": "TEST", "signal": "BUY", "score": 30, "price": 100.0}], "2026-01-01", log)

    rows = backtest.recent_signals(limit=10, horizons=(1,), log_path=log, history_path=hist_file)
    assert rows[0]["outcomes"]["1"] == pytest.approx(10.0)


def test_loading_a_corrupt_log_returns_empty_rather_than_raising(tmp_path):
    bad = tmp_path / "signal_log.json"
    bad.write_text("{not json")
    assert backtest.load_signal_log(bad) == []
    assert backtest.load_history(bad) == {}


# ─── Real engine ──────────────────────────────────────────────────────────────

def test_real_signal_engine_is_wired_in():
    """Guards the contract the backtest depends on: the server exposes an
    ``analyzer``/``engine`` pair whose ``score_full`` returns a known tier."""
    analyzer, engine = backtest.load_engine()

    prices = [100.0 + math.sin(i / 3) * 5 for i in range(60)]
    df = backtest.frame_from_rows(make_history(prices)["TEST"])
    observations = backtest.observations_for_symbol("TEST", df, analyzer, engine, (5,), 20)

    assert observations
    assert all(o.signal in backtest.TIER_ORDER for o in observations)
    assert all(-100 <= o.score <= 100 for o in observations)
