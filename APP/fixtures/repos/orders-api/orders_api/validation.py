"""Input normalisation helpers."""

import re

POSTCODE_RE = re.compile(r"^[A-Z]{1,2}[0-9][A-Z0-9]? ?[0-9][A-Z]{2}$")


def normalise_sku(sku: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]", "", sku).upper()
    if len(cleaned) < 4:
        raise ValueError("SKU too short")
    return f"{cleaned[:3]}-{cleaned[3:]}"


def validate_postcode(postcode: str) -> bool:
    return bool(POSTCODE_RE.match(postcode.strip().upper()))


def parse_quantity(value: str) -> int:
    value = value.strip()
    if not value.isdigit():
        raise ValueError("quantity must be a whole number")
    qty = int(value)
    if qty == 0 or qty > 99:
        raise ValueError("quantity out of range")
    return qty


def mask_email(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return f"{local[0]}***@{domain}" if local else f"***@{domain}"
