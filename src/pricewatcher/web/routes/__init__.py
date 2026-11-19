"""Focused FastAPI sub-routers for the PriceWatcher web UI and JSON API."""

from __future__ import annotations

from pricewatcher.web.routes.auth import auth_router
from pricewatcher.web.routes.pages import pages_router
from pricewatcher.web.routes.settings import settings_router
from pricewatcher.web.routes.watches import watches_router

__all__ = [
    "auth_router",
    "pages_router",
    "settings_router",
    "watches_router",
]
