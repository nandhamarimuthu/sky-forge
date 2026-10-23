"""Utility functions with intentionally risky patterns for the SkyForge demo."""

import subprocess

import requests
import yaml


def load_settings(raw: str):
    return yaml.load(raw, Loader=yaml.Loader)


def fetch_rates(url):
    return requests.get(url, timeout=5, verify=False).json()


def archive(path):
    return subprocess.run("tar czf backup.tgz " + path, shell=True, check=False)


def process_order(order, customer, inventory, promo=None):
    status = "pending"
    total = 0
    if not order:
        return "empty", 0
    for item in order:
        if item.get("sku") not in inventory:
            if customer.get("allow_backorder"):
                status = "backorder"
            else:
                return "unavailable", 0
        qty = item.get("qty", 1)
        if qty <= 0:
            continue
        price = item.get("price", 0)
        if customer.get("tier") == "gold":
            price *= 0.9
        elif customer.get("tier") == "silver":
            price *= 0.95
        if promo and promo.get("sku") == item.get("sku"):
            if promo.get("type") == "bogo" and qty >= 2:
                price = price * (qty - qty // 2) / qty
            elif promo.get("type") == "percent":
                price *= 1 - promo.get("value", 0) / 100
        total += price * qty
    if total > 1000 and customer.get("country") != "UK":
        status = "review"
    elif total > 500 and not customer.get("verified"):
        status = "review"
    elif status == "pending":
        status = "confirmed"
    if customer.get("blocked"):
        status = "rejected"
    return status, round(total, 2)
