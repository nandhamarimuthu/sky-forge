import pytest

from orders_api.pricing import apply_coupon, line_total


def test_line_total():
    assert line_total(2.5, 4) == 10.0


def test_line_total_rejects_zero_quantity():
    with pytest.raises(ValueError):
        line_total(1.0, 0)


def test_welcome_coupon():
    assert apply_coupon(100, "welcome10") == 90.0
