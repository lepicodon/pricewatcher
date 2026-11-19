"""Source adapters package and registry."""

from __future__ import annotations

from pricewatcher.adapters.appleinsider import AppleInsiderAdapter
from pricewatcher.adapters.base import FetchOutcome, Listing, SourceAdapter, sanitize_listing_url
from pricewatcher.adapters.html_css import HtmlCssAdapter
from pricewatcher.adapters.json_api import JsonApiAdapter
from pricewatcher.adapters.rss import RssAdapter

_ADAPTERS: dict[str, SourceAdapter] = {
    "rss": RssAdapter(),
    "json_api": JsonApiAdapter(),
    "html_css": HtmlCssAdapter(),
    "appleinsider": AppleInsiderAdapter(),
}


def get_adapter(name: str) -> SourceAdapter:
    adapter = _ADAPTERS.get(name)
    if adapter is None:
        raise ValueError(f"Unknown source adapter: {name!r}")
    return adapter


__all__ = [
    "AppleInsiderAdapter",
    "FetchOutcome",
    "HtmlCssAdapter",
    "JsonApiAdapter",
    "Listing",
    "RssAdapter",
    "SourceAdapter",
    "get_adapter",
    "sanitize_listing_url",
]
