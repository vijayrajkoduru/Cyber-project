from fastapi import FastAPI

from app.config import get_settings
from app.routers import items


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, debug=settings.debug)

    app.include_router(items.router)

    @app.get("/")
    def root() -> dict:
        return {"service": settings.app_name, "docs": "/docs"}

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
