"""Generic rule matcher, spec extractors, and tier grouping."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import logging
from typing import Any

import regex

from pricewatcher.adapters.base import Listing, detect_condition, is_monthly_only_price
from pricewatcher.config import ExtractorConfig, RulesConfig

logger = logging.getLogger("pricewatcher.matcher")

EXTRACTOR_REGEX_TIMEOUT_SECONDS = 0.05


@lru_cache(maxsize=256)
def _compile_extractor_pattern(pattern: str) -> regex.Pattern[str]:
    return regex.compile(pattern, regex.IGNORECASE)


@dataclass
class MatchResult:
    matched: bool
    reason: str
    extracted: dict[str, Any] = field(default_factory=dict)
    tier_key: str = "default"
    normalized_condition: str = "new"


def _parse_extractor_match(name: str, cfg: ExtractorConfig, text: str) -> int | float | str | None:
    try:
        pattern = _compile_extractor_pattern(cfg.pattern)
    except regex.error as exc:
        logger.warning(
            "Extractor %r failed to compile (pattern=%r): %s", name, cfg.pattern[:64], exc
        )
        return None

    try:
        matches = list(pattern.finditer(text, timeout=EXTRACTOR_REGEX_TIMEOUT_SECONDS))
    except TimeoutError:
        logger.warning(
            "Extractor %r regex timed out after %.2fs (pattern=%r)",
            name,
            EXTRACTOR_REGEX_TIMEOUT_SECONDS,
            cfg.pattern[:64],
        )
        return None
    if not matches:
        return None

    parsed_candidates: list[tuple[str, int | float | str]] = []
    for m in matches:
        matched_text = m.group(0)
        if cfg.type == "storage_gb":
            tb_val = m.group(1) if m.lastindex and m.lastindex >= 1 else None
            gb_val = m.group(2) if m.lastindex and m.lastindex >= 2 else None
            if tb_val:
                val: int | float | str = int(tb_val) * 1024
            elif gb_val:
                val = int(gb_val)
            else:
                group_str = next((g for g in m.groups() if g is not None), matched_text)
                num = int(regex.sub(r"\D+", "", group_str))
                val = num * 1024 if "tb" in matched_text.lower() else num
        elif cfg.type == "int":
            group_str = next((g for g in m.groups() if g is not None), matched_text)
            val = int(group_str)
        elif cfg.type == "float":
            group_str = next((g for g in m.groups() if g is not None), matched_text)
            val = float(group_str)
        else:
            group_str = next((g for g in m.groups() if g is not None), matched_text)
            val = group_str.strip()

        parsed_candidates.append((matched_text.lower(), val))

    # Disambiguate RAM vs SSD when titles list two bare GB numbers (e.g. "64GB, 512GB")
    if name == "ram_gb" and len(parsed_candidates) > 1:
        labeled = [
            v
            for txt, v in parsed_candidates
            if any(tok in txt for tok in ("memory", "ram", "unified"))
        ]
        if labeled:
            return labeled[0]
        under_512 = [v for _, v in parsed_candidates if isinstance(v, (int, float)) and v < 512]
        if under_512:
            return under_512[0]

    if name == "ssd_gb" and len(parsed_candidates) > 1:
        labeled = [
            v for txt, v in parsed_candidates if any(tok in txt for tok in ("tb", "ssd", "storage"))
        ]
        if labeled:
            return labeled[0]
        return parsed_candidates[-1][1]

    return parsed_candidates[0][1]


def format_tier_value(key: str, value: Any) -> str:
    if key == "ram_gb" and isinstance(value, (int, float)):
        return f"{int(value)}GB"
    if key == "ssd_gb" and isinstance(value, (int, float)):
        gb = int(value)
        if gb >= 1024 and gb % 1024 == 0:
            return f"{gb // 1024}TB"
        return f"{gb}GB"
    return str(value)


def build_tier_key(
    tier_by: list[str],
    extracted: dict[str, Any],
    condition: str,
) -> str:
    if not tier_by:
        return "default"
    parts: list[str] = []
    for field_name in tier_by:
        if field_name == "condition":
            parts.append(condition)
        elif field_name in extracted and extracted[field_name] is not None:
            parts.append(format_tier_value(field_name, extracted[field_name]))
        else:
            parts.append("unknown")
    return " / ".join(parts) if parts else "default"


def evaluate_listing(listing: Listing, rules: RulesConfig) -> MatchResult:
    title = listing.title.strip()
    if not title:
        return MatchResult(matched=False, reason="empty title")

    if listing.raw_specs.get("is_monthly_only"):
        return MatchResult(matched=False, reason="monthly financing snippet only")
    if not listing.raw_specs.get("structured_price") and is_monthly_only_price(title):
        return MatchResult(matched=False, reason="monthly financing price only")

    if rules.require_in_stock and not listing.in_stock:
        return MatchResult(matched=False, reason="out of stock")

    normalized_cond = detect_condition(
        f"{listing.condition} {title}", default=listing.condition.lower() or "new"
    )
    allowed_conds = {c.lower() for c in rules.conditions_allowed}
    if allowed_conds and normalized_cond not in allowed_conds:
        return MatchResult(matched=False, reason=f"condition {normalized_cond!r} not allowed")

    lower_title = title.lower()
    search_blob = f"{title} {listing.raw_specs.get('extra_text', '')}".lower()

    # Check exclusions against title first (and extra_text if provided)
    for kw in rules.exclude_keywords:
        if kw and kw.lower() in lower_title:
            return MatchResult(matched=False, reason=f"excluded keyword {kw!r}")

    # Each group in include_keyword_groups is an AND-group of OR-alternatives
    for group in rules.include_keyword_groups:
        if not group:
            continue
        if not any(term.lower() in search_blob for term in group if term):
            return MatchResult(matched=False, reason=f"missing keyword group {group!r}")

    if listing.price < rules.price.min or listing.price > rules.price.max:
        return MatchResult(
            matched=False,
            reason=f"price ${listing.price:.2f} outside [${rules.price.min:.2f}, ${rules.price.max:.2f}]",
        )

    extracted: dict[str, Any] = {}
    extract_text = f"{title} {listing.raw_specs.get('spec_text', '')}".strip()
    for name, ext_cfg in rules.extractors.items():
        val = _parse_extractor_match(name, ext_cfg, extract_text)
        if val is None:
            if ext_cfg.required:
                return MatchResult(matched=False, reason=f"missing required spec {name!r}")
            continue

        if isinstance(val, (int, float)):
            if ext_cfg.min is not None and val < ext_cfg.min:
                return MatchResult(
                    matched=False,
                    reason=f"{name}={val} below min {ext_cfg.min}",
                )
            if ext_cfg.max is not None and val > ext_cfg.max:
                return MatchResult(
                    matched=False,
                    reason=f"{name}={val} above max {ext_cfg.max}",
                )
        extracted[name] = val

    tier_key = build_tier_key(rules.tier_by, extracted, normalized_cond)
    return MatchResult(
        matched=True,
        reason="matched",
        extracted=extracted,
        tier_key=tier_key,
        normalized_condition=normalized_cond,
    )
