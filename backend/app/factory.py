import logging

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import get_settings
from app.core.rate_limit import limiter
from app.routers import auth, findings, scans

logger = logging.getLogger(__name__)

API_DESCRIPTION = """
Full-stack API vulnerability scanner targeting the OWASP API Security Top 10.

### Authentication
Register an account, then log in to receive a JWT bearer token. Pass it as
`Authorization: Bearer <token>` on every subsequent request.

### Scanning
Point a scan at a target base URL and a list of endpoint paths (with `{id}`
-style placeholders for object routes). The target host must be present in
the server's `ALLOWED_SCAN_HOSTS` allow-list -- this tool is meant for
testing infrastructure you own or are explicitly authorized to assess, and
it will refuse to scan anything else with a 400.

### Rate limits
The authentication endpoints (`/api/auth/login`, `/api/auth/register`) are
rate-limited per client IP to blunt credential-stuffing and registration
spam. Exceeding the limit returns `429 Too Many Requests`.
"""


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description=API_DESCRIPTION,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Never leak stack traces / internals to clients.
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    app.include_router(auth.router)
    app.include_router(scans.router)
    app.include_router(findings.router)

    @app.get("/api/health", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
