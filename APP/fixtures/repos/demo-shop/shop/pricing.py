"""Pricing helpers for the demo shop (intentionally only partially tested)."""

from __future__ import annotations


def calculate_discount(price: float, percent: int) -> float:
    if price < 0:
        raise ValueError("price must be positive")
    if percent <= 0:
        return round(price, 2)
    if percent >= 100:
        return 0.0
    return round(price * (100 - percent) / 100, 2)


def apply_tax(amount: float, region: str = "UK") -> float:
    rates = {"UK": 0.2, "IE": 0.23, "DE": 0.19}
    rate = rates.get(region.upper())
    if rate is None:
        raise KeyError(region)
    return round(amount * (1 + rate), 2)


def slugify(text: str) -> str:
    out = []
    for ch in text.strip().lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-")


def shipping_band(weight: int) -> str:
    if weight <= 0:
        return "invalid"
    if weight < 2:
        return "small"
    if weight < 10:
        return "medium"
    if weight < 30:
        return "large"
    return "freight"


def loyalty_points(amount: float, tier: str = "basic") -> int:
    multiplier = {"basic": 1, "silver": 2, "gold": 3}.get(tier, 1)
    return int(amount // 10) * multiplier
