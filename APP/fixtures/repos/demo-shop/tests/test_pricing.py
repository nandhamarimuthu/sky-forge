from shop.pricing import calculate_discount


def test_discount_basic():
    assert calculate_discount(100.0, 10) == 90.0


def test_discount_zero_percent():
    assert calculate_discount(50.0, 0) == 50.0
