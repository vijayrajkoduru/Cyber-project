"""DNS Records — placeholder. Real implementation to be added."""
from fastapi import APIRouter
router = APIRouter()
def register(app):
    app.include_router(router)
