"""Base Listing model, SourceAdapter protocol, and shared price/text helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from pricewatcher.config import SourceConfig

if TYPE_CHECKING:
    from pricewatcher.http_client import HttpContext

MONTHLY_FINANCING_RE = re.compile(
    r"(?:\$\s*[\d,]+(?:\.\d{1,2})?\s*(?:/\s*mo(?:nth)?|per\s+month|a\s+month|mo\.?\b)|"
    r"\$\s*[\d,]+(?:\.\d{1,2})?\s+for\s+\d+\s+mo(?:nths?)?|"
    r"starting\s+at\s+\$\s*[\d,]+(?:\.\d{1,2})?\s*/\s*mo|"
    r"\b\d+(?:\.\d+)?%\s*apr\b|"
    r"\bper\s+month\b)",
    re.IGNORECASE,
)
PRICE_TOKEN_RE = re.compile(r"\$\s*([1-9]\d{0,2}(?:,\d{3})+|\d{1,6})(?:\.(\d{2}))?")
PROMO_CODE_RE = re.compile(
    r"(?:promo\s*code|coupon\s*code|coupon|code)\s*[:#]?\s*([A-Z0-9]{4,20})",
    re.IGNORECASE,
)


def strip_monthly_financing(text: str) -> str:
    """Remove monthly installment / APR phrases so $316/mo is never read as a price."""
    return MONTHLY_FINANCING_RE.sub(" ", text)


def is_monthly_only_price(text: str) -> bool:
    """Return True if dollar amounts appear ONLY as monthly financing payments."""
    raw_prices = PRICE_TOKEN_RE.findall(text)
    if not raw_prices:
        return False
    cleaned = strip_monthly_financing(text)
    remaining_prices = PRICE_TOKEN_RE.findall(cleaned)
    return len(remaining_prices) == 0


def extract_purchase_price(text: str, min_reasonable: float = 1.0) -> float | None:
    """Extract a realistic one-time purchase price, ignoring monthly financing amounts."""
    cleaned = strip_monthly_financing(text)
    candidates: list[float] = []
    for whole, cents in PRICE_TOKEN_RE.findall(cleaned):
        num_str = whole.replace(",", "")
        if cents:
            num_str = f"{num_str}.{cents}"
        try:
            val = float(num_str)
        except ValueError:
            continue
        if val >= min_reasonable:
            candidates.append(val)
    if not candidates:
        return None
    return candidates[0]


def extract_promo_code(text: str) -> str | None:
    match = PROMO_CODE_RE.search(text)
    if not match:
        return None
    return match.group(1).upper()


def detect_condition(text: str, default: str = "new") -> str:
    lower = text.lower()
    if any(
        tok in lower for tok in ("refurbished", "refurb", "certified pre-owned", "cpo", "renewed")
    ):
        return "refurbished"
    if any(tok in lower for tok in ("open-box", "open box")):
        return "open-box"
    if any(tok in lower for tok in ("used", "pre-owned", "preowned", "usedcondition")):
        return "used"
    return default


def sanitize_listing_url(raw_url: str | None) -> str:
    """Allow only http/https listing URLs with a non-empty netloc, else return empty string."""
    if not raw_url or not isinstance(raw_url, str):
        return ""
    cleaned = raw_url.strip()
    if not cleaned or any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        return ""
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    if not parsed.netloc or not parsed.hostname:
        return ""
    return cleaned


class Listing(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source_name: str
    merchant: str
    title: str
    url: str
    price: float
    currency: str = "USD"
    condition: str = "new"
    in_stock: bool = True
    promo_code: str | None = None
    raw_specs: dict[str, Any] = Field(default_factory=dict)


@dataclass
class FetchOutcome:
    listings: list[Listing] = field(default_factory=list)
    http_status: int | None = None
    error: str | None = None
    latency_ms: int = 0


class SourceAdapter(Protocol):
    async def fetch(
        self, source: SourceConfig, http_ctx: HttpContext | None = None
    ) -> FetchOutcome:
        """Fetch and normalize listings from a single configured source."""
        ...
