# RockyCrypt — NSE Kenya Analytics

A FastAPI backend plus a single-file frontend that scores every stock on the
Nairobi Securities Exchange each day with a technical-analysis engine, publishes
signals (`STRONG BUY` … `STRONG SELL`), and tracks how those signals actually
performed.

```
rockycrypt_server.py     FastAPI app: market data, TA engine, auth, payments, admin
rockycrypt_modules.py    optional feature modules registered at startup
rockycrypt_v2.html       the entire frontend (vanilla JS SPA)
backtest.py              signal backtester + append-only track record
technical_indicators.py  indicator library
nse_real_time_data.py    live NSE feed client
ml_trading_signals.py    experimental ML models (not a headline feature)
advanced_screener.py     multi-criteria screener
*_security.py, gdpr_*    auth hardening, fraud, compliance modules
tests/                   pytest suite
```

Missing optional modules are tolerated: `rockycrypt_modules.register()` skips
their routes rather than failing startup.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                              # then fill in the values
python rockycrypt_server.py                       # http://127.0.0.1:5000
```

On Windows, `start_with_env.ps1` loads `.env` and starts the server.
Docker: `docker compose up --build` (see `docker-compose.yml` / `nginx.conf`).

**Never commit `.env`.** It is git-ignored; `.env.example` documents every
variable. `ROCKYCRYPT_JWT_SECRET`, `ROCKYCRYPT_ADMIN_SECRET` and the Paystack
keys are required in production and validated at boot.

## Signal track record

The engine's credibility rests on measured results, not on the number of
endpoints. Two mechanisms produce them:

- **Backtest** — replays `data/price_history.json` and scores every symbol on
  every day with the live analyzer/engine. Day *i* is scored from rows `0..i`
  only, so there is no lookahead.
- **Track record** — every analysis run appends its calls to
  `data/signal_log.json`, which is append-only: an already-logged
  `(date, symbol)` is never rewritten, so the record cannot be re-tuned after
  the fact.

Both report, per signal tier and per horizon (5/20/60 sessions): `n`,
`hit_rate`, `avg_return`, `median_return`, `avg_excess_return`, `best`, `worst`
and an indicative `max_drawdown`. Hit rate is direction-aware — a `SELL`
followed by a fall is a hit. Excess return is measured against an equal-weight
basket of every symbol priced the same day, because "everything went up" is not
a signal.

```bash
python backtest.py                        # backtest the stored history
python backtest.py --horizons 5,20 --symbol SCOM
python backtest.py --track-record         # score signals actually emitted
python backtest.py --json report.json
```

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /api/track-record` | public | tier/horizon performance of emitted signals |
| `GET /api/track-record/signals?limit=` | public | recent signals with realised outcomes |
| `GET /api/backtest?horizons=&symbol=` | admin | on-demand replay of stored history |

Reports always carry a `warnings` list (thin history, gross returns, overlapping
windows). Publish the warnings alongside the numbers — the point of the track
record is that it is honest.

**Current data caveat:** `price_history.json` holds only a handful of sessions
per symbol, so today's output is structurally correct but statistically
meaningless. Backfilling NSE history, and running the collector so it can never
miss a day, is the prerequisite for publishing any of these numbers.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests -q
```
