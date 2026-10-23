"""Pure pricing rules: line totals, coupons, shipping and VAT."""

from decimal import ROUND_HALF_UP, Decimal

VAT_RATES = {"GB": 0.20, "IE": 0.23, "DE": 0.19, "FR": 0.20, "NL": 0.21}
SHIPPING_ZONES = {"GB": 1, "IE": 2, "FR": 2, "DE": 2, "NL": 2}


def money(value: float) -> float:
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def line_total(unit_price: float, quantity: int) -> float:
    if quantity <= 0:
        raise ValueError("quantity must be positive")
    if unit_price < 0:
        raise ValueError("unit price cannot be negative")
    return money(unit_price * quantity)


def apply_coupon(subtotal: float, code: str) -> float:
    """Return the discounted subtotal for a coupon code."""
    code = code.strip().upper()
    if not code:
        return money(subtotal)
    if code == "WELCOME10":
        return money(subtotal * 0.9)
    if code == "FREESHIP":
        return money(subtotal)
    if code.startswith("SAVE") and code[4:].isdigit():
        amount = int(code[4:])
        if amount > 50:
            raise ValueError("coupon value too large")
        return money(max(subtotal - amount, 0))
    if code == "VIP25" and subtotal >= 200:
        return money(subtotal * 0.75)
    raise ValueError(f"unknown coupon {code}")


def shipping_cost(weight_kg: float, country: str, express: bool = False) -> float:
    zone = SHIPPING_ZONES.get(country.upper(), 3)
    if weight_kg <= 0:
        raise ValueError("weight must be positive")
    if weight_kg <= 2:
        base = 3.99
    elif weight_kg <= 10:
        base = 7.49
    elif weight_kg <= 30:
        base = 14.99
    else:
        base = 14.99 + (weight_kg - 30) * 0.5
    if zone == 2:
        base *= 1.6
    elif zone == 3:
        base *= 2.4
    if express:
        base += 9.0 if zone == 1 else 15.0
    return money(base)


def vat_for(country: str, amount: float) -> float:
    rate = VAT_RATES.get(country.upper())
    if rate is None:
        return 0.0
    return money(amount * rate)


def order_total(lines: list, country: str, coupon: str = "", weight_kg: float = 1.0, express: bool = False) -> dict:
    subtotal = sum(line_total(price, qty) for price, qty in lines)
    discounted = apply_coupon(subtotal, coupon) if coupon else money(subtotal)
    shipping = 0.0 if coupon.strip().upper() == "FREESHIP" or discounted >= 75 else shipping_cost(weight_kg, country, express)
    vat = vat_for(country, discounted + shipping)
    return {"subtotal": money(subtotal), "discounted": discounted, "shipping": shipping, "vat": vat,
            "total": money(discounted + shipping + vat)}


def split_payment(total: float, parts: int) -> list:
    if parts < 1:
        raise ValueError("parts must be at least 1")
    cents = int(round(total * 100))
    share, remainder = divmod(cents, parts)
    return [(share + (1 if i < remainder else 0)) / 100 for i in range(parts)]


def loyalty_points(total: float, tier: str = "standard") -> int:
    multiplier = {"standard": 1, "silver": 1.5, "gold": 2, "platinum": 3}.get(tier.lower(), 1)
    return int(total * multiplier)
