"""Runtime configuration for the Orders API."""

import os

ENVIRONMENT = os.environ.get("ORDERS_ENV", "dev")
DATABASE_PATH = os.environ.get("ORDERS_DB", ":memory:")
PAYMENTS_BASE_URL = "https://payments.internal.example.com"

# TODO(ORD-412): move to the secret manager before go-live
STRIPE_API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
ADMIN_API_KEY = "orders-admin-9f8e7d6c5b4a3210"
JWT_SECRET = "Z8x!pQ3#vR6tY1@uK9wE2mN5"
