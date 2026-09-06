"""
RockyCrypt Signal Backtester & Track Record
===========================================

Answers the only question that matters to a paying user: *do the signals work?*

Two related jobs live here:

1. **Backtest** — replay the accumulated OHLCV history in ``data/price_history.json``
   and score every symbol on every day with the *live* engine
   (``rockycrypt_server.TechnicalAnalyzer`` + ``SignalEngine``), then measure what
   actually happened over the following N sessions. No lookahead: the indicators
   for day *i* are computed from rows ``0..i`` only.

2. **Track record** — an append-only log of the signals the running server has
   actually emitted (``data/signal_log.json``), evaluated against later prices.
   The backtest says how the rules would have done; the track record says how
   they *did* do, in public, and cannot be quietly re-tuned after the fact.

Both produce the same summary shape, keyed by signal tier
(``STRONG BUY``/``BUY``/…) and horizon (5/20/60 sessions):

    n, hit_rate, avg_return, median_return, avg_excess_return, best, worst,
    max_drawdown

``avg_excess_return`` is measured against an equal-weight basket of every symbol
priced on the same day — the honest benchmark, since "everything went up" is not
a signal.

CLI
---
    python backtest.py                          # backtest the default history file
    python backtest.py --horizons 5,20 --symbol SCOM
    python backtest.py --track-record           # evaluate emitted signals instead
    python backtest.py --json report.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

import pandas as pd

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
HISTORY_FILE = DATA_DIR / "price_history.json"
SIGNAL_LOG_FILE = DATA_DIR / "signal_log.json"

DEFAULT_HORIZONS: tuple[int, ...] = (5, 20, 60)
MIN_HISTORY_ROWS = 20        # matches the server's full-TA threshold
SIGNAL_LOG_MAX_ENTRIES = 200_000

TIER_ORDER = [
    "STRONG BUY",
    "BUY",
    "LEAN BULLISH",
    "NEUTRAL",
    "LEAN BEARISH",
    "SELL",
    "STRONG SELL",
]
BULLISH_TIERS = {"STRONG BUY", "BUY", "LEAN BULLISH"}
BEARISH_TIERS = {"STRONG SELL", "SELL", "LEAN BEARISH"}


# ─── Engine access ────────────────────────────────────────────────────────────

def load_engine() -> tuple[Any, Any]:
    """Return the live ``(analyzer, engine)`` pair from the server module.

    Imported lazily so this module can be used (and tested) with a stub engine
    without pulling in the whole FastAPI app.
    """
    import rockycrypt_server

    return rockycrypt_server.analyzer, rockycrypt_server.engine


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class Observation:
    """One scored symbol on one day, with what happened next."""

    date: str
    symbol: str
    score: int
    signal: str
    price: float
    forward_returns: dict[int, float | None] = field(default_factory=dict)
    excess_returns: dict[int, float | None] = field(default_factory=dict)

    def to_json(self) -> dict:
        d = asdict(self)
        d["forward_returns"] = {str(k): v for k, v in self.forward_returns.items()}
        d["excess_returns"] = {str(k): v for k, v in self.excess_returns.items()}
        return d


@dataclass
class TierStats:
    tier: str
    horizon: int
    n: int
    hit_rate: float | None
    avg_return: float | None
    median_return: float | None
    avg_excess_return: float | None
    best: float | None
    worst: float | None
    max_drawdown: float | None


# ─── History helpers ──────────────────────────────────────────────────────────

def load_history(path: str | Path = HISTORY_FILE) -> dict[str, list[dict]]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def frame_from_rows(rows: Sequence[dict]) -> pd.DataFrame:
    """Build the OHLCV frame the analyzer expects from raw history rows."""
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(list(rows))
    if "date" not in df.columns or "close" not in df.columns:
        return pd.DataFrame()
    df["Date"] = pd.to_datetime(df["date"], errors="coerce")
    df = df.dropna(subset=["Date", "close"])
    df = df.sort_values("Date").drop_duplicates(subset="Date", keep="last").reset_index(drop=True)
    df = df.rename(columns={
        "open": "Open", "high": "High", "low": "Low",
        "close": "Close", "volume": "Volume",
    })
    for col in ("Open", "High", "Low", "Close", "Volume"):
        if col not in df.columns:
            df[col] = df["Close"] if col != "Volume" else 0
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["Close"])
    return df[df["Close"] > 0].reset_index(drop=True)


def _market_returns(frames: dict[str, pd.DataFrame], horizons: Sequence[int]) -> dict[str, dict[int, float]]:
    """Equal-weight benchmark: mean forward return of every symbol, per date."""
    buckets: dict[str, dict[int, list[float]]] = {}
    for df in frames.values():
        closes = df["Close"].tolist()
        dates = df["Date"].dt.strftime("%Y-%m-%d").tolist()
        for i, base in enumerate(closes):
            if base <= 0:
                continue
            day = buckets.setdefault(dates[i], {})
            for h in horizons:
                j = i + h
                if j < len(closes):
                    day.setdefault(h, []).append((closes[j] - base) / base * 100.0)
    return {
        date: {h: sum(vals) / len(vals) for h, vals in per_h.items() if vals}
        for date, per_h in buckets.items()
    }


# ─── Backtest ─────────────────────────────────────────────────────────────────

def observations_for_symbol(
    symbol: str,
    df: pd.DataFrame,
    analyzer: Any,
    engine: Any,
    horizons: Sequence[int] = DEFAULT_HORIZONS,
    min_history: int = MIN_HISTORY_ROWS,
) -> list[Observation]:
    """Score every day that has enough prior history, and attach forward returns.

    Day *i* is scored using rows ``0..i`` inclusive — exactly the information the
    server would have had that evening — so the result contains no lookahead.
    """
    out: list[Observation] = []
    n = len(df)
    if n < min_history:
        return out

    closes = df["Close"].tolist()
    dates = df["Date"].dt.strftime("%Y-%m-%d").tolist()

    for i in range(min_history - 1, n):
        window = df.iloc[: i + 1]
        indicators = analyzer.analyze(window)
        if not indicators:
            continue
        scored = engine.score_full(indicators)
        base = closes[i]
        if base <= 0:
            continue

        obs = Observation(
            date=dates[i],
            symbol=symbol,
            score=int(scored["score"]),
            signal=scored["signal"],
            price=round(float(base), 4),
        )
        for h in horizons:
            j = i + h
            obs.forward_returns[h] = (
                round((closes[j] - base) / base * 100.0, 4) if j < n else None
            )
        out.append(obs)
    return out


def run_backtest(
    history: dict[str, list[dict]] | None = None,
    horizons: Sequence[int] = DEFAULT_HORIZONS,
    min_history: int = MIN_HISTORY_ROWS,
    symbols: Iterable[str] | None = None,
    analyzer: Any = None,
    engine: Any = None,
) -> dict:
    """Replay the full history and summarise signal performance by tier."""
    if history is None:
        history = load_history()
    if analyzer is None or engine is None:
        analyzer, engine = load_engine()

    wanted = set(symbols) if symbols else None
    frames = {
        sym: frame_from_rows(rows)
        for sym, rows in history.items()
        if wanted is None or sym in wanted
    }
    frames = {s: df for s, df in frames.items() if not df.empty}

    benchmark = _market_returns(frames, horizons)

    observations: list[Observation] = []
    for sym, df in frames.items():
        for obs in observations_for_symbol(sym, df, analyzer, engine, horizons, min_history):
            market = benchmark.get(obs.date, {})
            for h in horizons:
                fwd = obs.forward_returns.get(h)
                mkt = market.get(h)
                obs.excess_returns[h] = (
                    round(fwd - mkt, 4) if fwd is not None and mkt is not None else None
                )
            observations.append(obs)

    return build_report(observations, horizons, frames, min_history)


def build_report(
    observations: list[Observation],
    horizons: Sequence[int],
    frames: dict[str, pd.DataFrame] | None = None,
    min_history: int = MIN_HISTORY_ROWS,
) -> dict:
    frames = frames or {}
    all_dates = sorted({o.date for o in observations})
    depth = sorted((len(df) for df in frames.values()), reverse=True)

    return {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "horizons": list(horizons),
        "min_history": min_history,
        "coverage": {
            "symbols": len(frames),
            "symbols_scored": len({o.symbol for o in observations}),
            "observations": len(observations),
            "first_date": all_dates[0] if all_dates else None,
            "last_date": all_dates[-1] if all_dates else None,
            "deepest_symbol_sessions": depth[0] if depth else 0,
            "median_symbol_sessions": int(statistics.median(depth)) if depth else 0,
        },
        "tiers": {
            tier: {
                str(h): asdict(stats)
                for h, stats in ((h, summarize_tier(observations, tier, h)) for h in horizons)
            }
            for tier in TIER_ORDER
        },
        "directional_accuracy": {
            str(h): _directional_accuracy(observations, h) for h in horizons
        },
        "warnings": _warnings(observations, frames, min_history),
    }


def summarize_tier(observations: Sequence[Observation], tier: str, horizon: int) -> TierStats:
    """Aggregate one signal tier at one horizon.

    ``hit_rate`` is direction-aware: a bearish tier scores a hit when the price
    falls. ``max_drawdown`` is the deepest peak-to-trough decline of an equity
    curve that compounds the tier's mean return per date — returns overlap
    between consecutive dates, so treat it as an indication, not a live P&L.
    """
    rows = [o for o in observations if o.signal == tier and o.forward_returns.get(horizon) is not None]
    if not rows:
        return TierStats(tier, horizon, 0, None, None, None, None, None, None, None)

    returns = [float(o.forward_returns[horizon]) for o in rows]
    excess = [float(o.excess_returns[horizon]) for o in rows if o.excess_returns.get(horizon) is not None]

    if tier in BEARISH_TIERS:
        hits = sum(1 for r in returns if r < 0)
    elif tier in BULLISH_TIERS:
        hits = sum(1 for r in returns if r > 0)
    else:
        hits = sum(1 for r in returns if abs(r) < 2.0)   # NEUTRAL = stayed put

    return TierStats(
        tier=tier,
        horizon=horizon,
        n=len(returns),
        hit_rate=round(hits / len(returns) * 100.0, 2),
        avg_return=round(sum(returns) / len(returns), 4),
        median_return=round(statistics.median(returns), 4),
        avg_excess_return=round(sum(excess) / len(excess), 4) if excess else None,
        best=round(max(returns), 4),
        worst=round(min(returns), 4),
        max_drawdown=_max_drawdown(rows, horizon),
    )


def _max_drawdown(rows: Sequence[Observation], horizon: int) -> float | None:
    per_date: dict[str, list[float]] = {}
    for o in rows:
        per_date.setdefault(o.date, []).append(float(o.forward_returns[horizon]))
    if not per_date:
        return None

    equity, peak, worst = 1.0, 1.0, 0.0
    for date in sorted(per_date):
        vals = per_date[date]
        equity *= 1.0 + (sum(vals) / len(vals)) / 100.0
        peak = max(peak, equity)
        worst = min(worst, equity / peak - 1.0)
    return round(worst * 100.0, 4)


def _directional_accuracy(observations: Sequence[Observation], horizon: int) -> dict:
    """How often a directional call (bullish/bearish) pointed the right way."""
    calls = [
        o for o in observations
        if o.signal in BULLISH_TIERS | BEARISH_TIERS
        and o.forward_returns.get(horizon) is not None
    ]
    if not calls:
        return {"n": 0, "accuracy": None}
    correct = sum(
        1 for o in calls
        if (o.signal in BULLISH_TIERS and float(o.forward_returns[horizon]) > 0)
        or (o.signal in BEARISH_TIERS and float(o.forward_returns[horizon]) < 0)
    )
    return {"n": len(calls), "accuracy": round(correct / len(calls) * 100.0, 2)}


def _warnings(
    observations: Sequence[Observation],
    frames: dict[str, pd.DataFrame],
    min_history: int,
) -> list[str]:
    """Honest caveats to render alongside the numbers."""
    warnings: list[str] = []
    if not frames:
        return ["No price history available — nothing to backtest."]

    shallow = sum(1 for df in frames.values() if len(df) < min_history)
    if shallow:
        warnings.append(
            f"{shallow} of {len(frames)} symbols have fewer than {min_history} sessions "
            "and were skipped entirely."
        )
    if len(observations) < 100:
        warnings.append(
            f"Only {len(observations)} scored observations — far too few to be statistically "
            "meaningful. Backfill history before publishing these numbers."
        )
    dates = {o.date for o in observations}
    if len(dates) < 60:
        warnings.append(
            f"History spans just {len(dates)} distinct sessions; results cover a single "
            "market regime."
        )
    warnings.append(
        "Returns are gross: no brokerage commission, spread, slippage or tax is deducted."
    )
    warnings.append(
        "Overlapping windows mean observations are not independent; treat drawdown as "
        "indicative only."
    )
    return warnings


# ─── Track record (append-only log of signals actually emitted) ───────────────

def record_signals(
    results: Sequence[dict],
    date: str | None = None,
    path: str | Path = SIGNAL_LOG_FILE,
) -> int:
    """Append the signals from one analysis run to the immutable log.

    Existing entries are never modified — that is the whole point of a track
    record. Re-running on a date that is already logged is a no-op, so a crash
    loop cannot inflate the log. Returns the number of entries appended.
    """
    date = date or datetime.now().strftime("%Y-%m-%d")
    log = load_signal_log(path)
    already = {(e.get("date"), e.get("symbol")) for e in log}

    appended = 0
    for r in results:
        symbol = r.get("symbol")
        signal = r.get("signal")
        price = r.get("price")
        if not symbol or not signal or not price:
            continue
        if (date, symbol) in already:
            continue
        log.append({
            "date": date,
            "symbol": symbol,
            "signal": signal,
            "score": r.get("score"),
            "price": round(float(price), 4),
            "data_days": r.get("data_days"),
            "recorded_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        })
        appended += 1

    if appended:
        if len(log) > SIGNAL_LOG_MAX_ENTRIES:
            log = log[-SIGNAL_LOG_MAX_ENTRIES:]
        _write_json(path, log)
    return appended


def load_signal_log(path: str | Path = SIGNAL_LOG_FILE) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _write_json(path: str | Path, data: Any) -> None:
    """Atomic write so a crash mid-save cannot truncate the log."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(p)


def evaluate_track_record(
    log: Sequence[dict] | None = None,
    history: dict[str, list[dict]] | None = None,
    horizons: Sequence[int] = DEFAULT_HORIZONS,
    log_path: str | Path = SIGNAL_LOG_FILE,
    history_path: str | Path = HISTORY_FILE,
) -> dict:
    """Score the signals the server actually published against later prices."""
    log = load_signal_log(log_path) if log is None else log
    history = load_history(history_path) if history is None else history

    frames = {sym: frame_from_rows(rows) for sym, rows in history.items()}
    frames = {s: df for s, df in frames.items() if not df.empty}
    benchmark = _market_returns(frames, horizons)

    index: dict[str, dict[str, int]] = {}
    for sym, df in frames.items():
        index[sym] = {d: i for i, d in enumerate(df["Date"].dt.strftime("%Y-%m-%d"))}

    observations: list[Observation] = []
    for entry in log:
        sym, date = entry.get("symbol"), entry.get("date")
        df = frames.get(sym)
        if df is None or date not in index.get(sym, {}):
            continue
        i = index[sym][date]
        closes = df["Close"].tolist()
        base = float(entry.get("price") or closes[i])
        if base <= 0:
            continue

        obs = Observation(
            date=date,
            symbol=sym,
            score=int(entry.get("score") or 0),
            signal=str(entry.get("signal") or ""),
            price=round(base, 4),
        )
        market = benchmark.get(date, {})
        for h in horizons:
            j = i + h
            fwd = round((closes[j] - base) / base * 100.0, 4) if j < len(closes) else None
            obs.forward_returns[h] = fwd
            mkt = market.get(h)
            obs.excess_returns[h] = round(fwd - mkt, 4) if fwd is not None and mkt is not None else None
        observations.append(obs)

    report = build_report(observations, horizons, frames)
    report["source"] = "track_record"
    report["logged_signals"] = len(log)
    report["evaluated_signals"] = len(observations)
    return report


def recent_signals(
    limit: int = 100,
    horizons: Sequence[int] = DEFAULT_HORIZONS,
    log_path: str | Path = SIGNAL_LOG_FILE,
    history_path: str | Path = HISTORY_FILE,
) -> list[dict]:
    """The most recent logged signals with their realised outcomes attached."""
    log = load_signal_log(log_path)[-max(limit, 0):]
    history = load_history(history_path)
    frames = {sym: frame_from_rows(rows) for sym, rows in history.items()}

    out: list[dict] = []
    for entry in reversed(log):
        sym, date = entry.get("symbol"), entry.get("date")
        row = dict(entry)
        row["outcomes"] = {}
        df = frames.get(sym)
        if df is not None and not df.empty:
            dates = df["Date"].dt.strftime("%Y-%m-%d").tolist()
            if date in dates:
                i = dates.index(date)
                closes = df["Close"].tolist()
                base = float(entry.get("price") or closes[i])
                for h in horizons:
                    j = i + h
                    row["outcomes"][str(h)] = (
                        round((closes[j] - base) / base * 100.0, 2) if j < len(closes) and base > 0 else None
                    )
        out.append(row)
    return out


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _print_report(report: dict) -> None:
    cov = report["coverage"]
    print(f"\nRockyCrypt {'track record' if report.get('source') == 'track_record' else 'backtest'}")
    print("=" * 78)
    print(
        f"symbols {cov['symbols_scored']}/{cov['symbols']} · observations {cov['observations']} · "
        f"{cov['first_date'] or '—'} → {cov['last_date'] or '—'} · "
        f"deepest {cov['deepest_symbol_sessions']} sessions"
    )

    for h in report["horizons"]:
        acc = report["directional_accuracy"][str(h)]
        print(f"\n── {h}-session horizon " + "─" * 52)
        print(f"{'tier':<14}{'n':>7}{'hit %':>9}{'avg %':>9}{'med %':>9}{'excess %':>11}{'worst %':>10}")
        for tier in TIER_ORDER:
            s = report["tiers"][tier][str(h)]
            if not s["n"]:
                continue
            def fmt(v: float | None) -> str:
                return "—" if v is None else f"{v:.2f}"
            print(
                f"{tier:<14}{s['n']:>7}{fmt(s['hit_rate']):>9}{fmt(s['avg_return']):>9}"
                f"{fmt(s['median_return']):>9}{fmt(s['avg_excess_return']):>11}{fmt(s['worst']):>10}"
            )
        if acc["n"]:
            print(f"directional accuracy: {acc['accuracy']:.2f}% over {acc['n']} calls")

    if report["warnings"]:
        print("\nCaveats")
        for w in report["warnings"]:
            print(f"  ! {w}")
    print()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Backtest RockyCrypt signals against price history.")
    parser.add_argument("--history", default=str(HISTORY_FILE), help="path to price_history.json")
    parser.add_argument("--log", default=str(SIGNAL_LOG_FILE), help="path to signal_log.json")
    parser.add_argument("--horizons", default="5,20,60", help="comma-separated forward horizons in sessions")
    parser.add_argument("--min-history", type=int, default=MIN_HISTORY_ROWS,
                        help="sessions required before a symbol is scored")
    parser.add_argument("--symbol", action="append", help="restrict to a symbol (repeatable)")
    parser.add_argument("--track-record", action="store_true",
                        help="evaluate emitted signals instead of replaying history")
    parser.add_argument("--json", help="write the full report to this path")
    args = parser.parse_args(argv)

    horizons = tuple(int(h) for h in args.horizons.split(",") if h.strip())

    if args.track_record:
        report = evaluate_track_record(horizons=horizons, log_path=args.log, history_path=args.history)
    else:
        report = run_backtest(
            history=load_history(args.history),
            horizons=horizons,
            min_history=args.min_history,
            symbols=args.symbol,
        )

    _print_report(report)
    if args.json:
        _write_json(args.json, report)
        print(f"report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
