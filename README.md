# sentry-api

Full-stack API vulnerability scanner targeting the OWASP API Security Top 10,
with configurable scan modules and a React dashboard.

Point it at an API you own or are explicitly authorized to test, and it
checks for:

| Module | OWASP Category | What it does |
|---|---|---|
| `rate_limit` | API4:2023 — Unrestricted Resource Consumption | Bursts concurrent requests at each endpoint and checks whether the server ever throttles (429 / rate-limit headers) |
| `auth_bypass` | API2:2023 — Broken Authentication | Tries no-auth, malformed tokens, JWT `alg:none` forgery, and verb tampering (e.g. DELETE slipping past GET-only auth) |
| `sqli` | API8:2023 — Security Misconfiguration / Injection | Error-signature detection plus boolean-based blind diffing on query params |
| `idor` | API1:2023 — Broken Object Level Authorization | Substitutes neighboring IDs into templated endpoints and flags missing ownership checks |

> **Safety note:** the backend enforces a host allow-list
> (`ALLOWED_SCAN_HOSTS`) so it refuses to scan hosts you haven't explicitly
> authorized. Add your target's hostname to `.env` before scanning it. This
> exists to keep the tool honest about its intended use — testing your own
> systems, not anyone else's.

## Stack

- **Backend:** FastAPI, SQLAlchemy (async), PostgreSQL, Alembic, httpx, aiohttp, JWT + bcrypt
- **Frontend:** React 18, TypeScript, Vite, React Router
- **Tooling:** Docker Compose, [`just`](https://github.com/casey/just) as the command runner

## Quick start

```bash
cp .env.example .env
# edit .env: set a real JWT_SECRET_KEY, add your target host to ALLOWED_SCAN_HOSTS

just up
```

Visit **http://localhost:8080** for the dashboard. The API itself is on
**http://localhost:8000** (docs at `/docs`).

Don't have `just`? Install it, or just run the equivalent
`docker compose up -d --build` directly.

```bash
curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin
```

## Common commands

```bash
just up                          # start everything
just logs                        # tail all logs
just migrate                     # apply pending migrations
just makemigration "add x"       # generate a new migration from model changes
just psql                        # psql shell into the scanner DB
just down                        # stop containers, keep data
just nuke                        # stop containers, wipe the DB volume
```

## Architecture

```
┌─────────────────────────────┐      ┌──────────────────────────────┐
│  React 18 / TypeScript      │      │  FastAPI backend              │
│  Vite dev server :5173      │◄────►│  :8000                        │
│  (proxied via :8080)        │ /api │                                │
└─────────────────────────────┘      │  ┌─────────────────────────┐  │
                                      │  │ auth router (JWT)        │ │
                                      │  ├─────────────────────────┤  │
                                      │  │ scans router             │  │
                                      │  │  → BackgroundTasks       │  │
                                      │  │  → scan_runner.py        │  │
                                      │  │      → scanner registry  │  │
                                      │  │        rate_limit        │  │
                                      │  │        auth_bypass       │  │
                                      │  │        sqli              │  │
                                      │  │        idor               │ │
                                      │  ├─────────────────────────┤  │
                                      │  │ findings router          │  │
                                      │  └─────────────────────────┘  │
                                      └───────────────┬──────────────┘
                                                       │
                                              ┌────────▼────────┐
                                              │  PostgreSQL      │
                                              │  users/scans/    │
                                              │  findings        │
                                              └──────────────────┘
```

Scans run as FastAPI `BackgroundTasks` rather than a separate worker queue —
simple enough for a single-instance deployment, and each scanner module opens
its own `httpx.AsyncClient` so modules run concurrently without blocking the
request/response cycle. Findings are written to Postgres as each module
finishes rather than batched at the end, so the dashboard can poll and show
partial results while a scan is still running.

## Testing

```bash
just test          # run the suite inside the backend container
just test-cov       # same, with a coverage report
```

The suite is split into two layers:

- **`tests/scanners/`** — unit tests for each of the 4 scanner modules,
  using [`respx`](https://lundberg.github.io/respx/) to mock the target
  API's responses. These test the detection *logic* in isolation: feed the
  rate-limit scanner a target that never 429s and confirm it flags a
  finding; feed it one that throttles and confirm it doesn't; feed the
  auth-bypass scanner a forged `alg:none` JWT and confirm it's caught; etc.
- **`tests/test_auth_router.py`** and **`tests/test_scan_creation.py`** —
  integration tests against the real FastAPI app, using an in-memory
  SQLite database instead of Postgres so they run with zero external
  services. This only works because the models use a portable `GUID`
  column type (`app/core/types.py`) rather than a Postgres-only UUID type —
  worth knowing about if you extend the schema later.

The integration tests also exercise the rate limiter directly: they hammer
`/api/auth/login` and `/api/auth/register` past their limits and assert on
the resulting `429`s, rather than just trusting the decorator is wired up
correctly.

Run locally without Docker:

```bash
cd backend
pip install -r requirements-dev.txt
pytest -v
```

## API rate limiting

`/api/auth/login` and `/api/auth/register` are rate-limited per client IP
using [`slowapi`](https://github.com/laurentS/slowapi) (login: 10/minute,
register: 5/minute). These are the two endpoints an attacker would actually
hit for credential stuffing or registration spam, so they're the ones that
get limits — the rest of the API sits behind JWT auth already, which is
the more relevant control there. Exceeding a limit returns `429 Too Many
Requests`. Limits are in-memory per-process by default; if you ever run
multiple backend replicas behind a load balancer, swap `slowapi`'s storage
backend for Redis (`app/core/rate_limit.py`) so limits are shared across
instances instead of reset per-replica.

## API docs

Full interactive docs (Swagger UI) are at `http://localhost:8000/docs` once
the stack is up, and `http://localhost:8000/redoc` for the Redoc view. Every
route has a request/response example baked into its OpenAPI schema (visible
in the "Example Value" tab in Swagger UI) and a docstring explaining
behavior that isn't obvious from the schema alone — e.g. that scan creation
returns immediately with `status: "pending"` while the actual scan runs in
the background, or that object lookups 404 rather than 403 for resources
you don't own (so you can't tell the difference between "not yours" and
"doesn't exist").

## Extending

Each scanner module is a small, self-contained class implementing
`BaseScanner.run() -> list[FindingDraft]` in `backend/app/scanners/`. To add
a new module (SSRF, XXE, GraphQL introspection, CORS misconfig, etc.):

1. Add a new file in `backend/app/scanners/`, subclass `BaseScanner`
2. Register it in `backend/app/scanners/__init__.py`'s `SCANNER_REGISTRY`
3. Add its key to `ScanModule` in `backend/app/schemas/scan.py` and the
   frontend's `ALL_MODULES` in `frontend/src/types/index.ts`

No other wiring needed — the scan runner and dashboard pick it up
automatically.

## Repo layout

```
backend/
  app/
    main.py            # ASGI entrypoint
    factory.py          # app factory, CORS, exception handling
    config.py            # settings (env-driven)
    database.py           # async engine/session
    core/                  # security (JWT/bcrypt), auth dependency
    models/                 # SQLAlchemy models
    schemas/                  # Pydantic request/response models
    routers/                   # auth / scans / findings
    scanners/                    # the 4 vulnerability modules + base classes
    services/                      # scan_runner orchestration
  alembic/                          # migrations
  Dockerfile
frontend/
  src/
    api/client.ts        # fetch wrapper + auth token handling
    hooks/useAuth.tsx      # auth context
    components/              # Navbar, badges
    pages/                      # Login, Register, Dashboard, NewScan, ScanDetail
  Dockerfile
docker-compose.yml
justfile
.env.example
```

## License

AGPL-3.0
