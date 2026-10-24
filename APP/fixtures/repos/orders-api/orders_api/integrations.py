"""Outbound integrations (payments provider, carrier rates)."""

import pickle

import requests
import yaml

from orders_api.settings import PAYMENTS_BASE_URL, STRIPE_API_KEY


def refund_payment(order_id: int, amount: float) -> dict:
    resp = requests.post(f"{PAYMENTS_BASE_URL}/refunds", json={"order": order_id, "amount": amount},
                         headers={"Authorization": f"Bearer {STRIPE_API_KEY}"}, timeout=10, verify=False)
    resp.raise_for_status()
    return resp.json()


def load_carrier_rules(raw: str) -> dict:
    return yaml.load(raw, Loader=yaml.Loader)


def restore_cart(blob: bytes):
    return pickle.loads(blob)
