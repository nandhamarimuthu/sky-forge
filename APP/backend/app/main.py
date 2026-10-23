from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import routes_findings, routes_platform, routes_projects, routes_scans
from app.core.config import BASE_DIR, get_settings
from app.core.errors import ApiError, install_error_handlers
from app.core.logging import configure_logging
from app.db.migrate import upgrade_database
from app.db.session import session_scope
from app.models import Setting
from app.services.container import get_container

log = logging.getLogger("skyforge")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    upgrade_database()
    c = get_container()
    with session_scope() as db:
        llm = db.get(Setting, "llm")
        if llm and llm.value:
            c.llm.model = llm.value.get("ollama_model", c.llm.model)
            c.llm.enabled = llm.value.get("llm_enabled", c.llm.enabled)
    c.worker.reconcile()
    status = c.llm.status(force=True)
    log.info("SkyForge AI ready — LLM reachable=%s model=%s available=%s, sandbox=%s, aws_mode=%s",
             status["reachable"], c.llm.model, status["model_available"], c.sandbox.available(), c.settings.aws_mode)
    yield
    c.worker.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="SkyForge AI API", version="0.1.0", lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    install_error_handlers(app)
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_list, allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                       allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request.state.rid = uuid.uuid4().hex[:12]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers["X-Request-ID"] = request.state.rid
        return response

    for r in (routes_platform.router, routes_projects.router, routes_scans.router, routes_findings.router):
        app.include_router(r, prefix="/api/v1")

    dist = (BASE_DIR / "frontend" / "dist").resolve()
    if (dist / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            if path.startswith("api/"):
                raise ApiError(404, "not_found", "Unknown API route")
            target = (dist / path).resolve()
            if path and target.is_file() and dist in target.parents:
                return FileResponse(target)
            return FileResponse(dist / "index.html")
    return app


app = create_app()
