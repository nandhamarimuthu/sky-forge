"""Stock and fulfilment rules."""

LOW_STOCK_THRESHOLD = 5


def stock_status(on_hand: int, reserved: int = 0) -> str:
    available = on_hand - reserved
    if available <= 0:
        return "out_of_stock"
    if available <= LOW_STOCK_THRESHOLD:
        return "low"
    return "in_stock"


def reorder_quantity(on_hand: int, daily_sales: float, lead_time_days: int = 7, safety_days: int = 3) -> int:
    if daily_sales < 0 or lead_time_days < 0:
        raise ValueError("negative inputs")
    target = daily_sales * (lead_time_days + safety_days)
    return max(0, int(round(target - on_hand)))


def pick_warehouse(postcode: str, warehouses: list) -> str:
    if not warehouses:
        raise ValueError("no warehouses")
    area = postcode.strip().upper()[:2]
    for name in warehouses:
        if name.upper().startswith(area):
            return name
    return warehouses[0]


def bundle_price(prices: list, discount_pct: float = 10.0) -> float:
    if not prices:
        return 0.0
    if not 0 <= discount_pct <= 50:
        raise ValueError("discount out of range")
    return round(sum(prices) * (1 - discount_pct / 100), 2)
