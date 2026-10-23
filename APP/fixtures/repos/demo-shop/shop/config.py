"""Configuration — contains deliberately unsafe example values for the SkyForge demo."""

import os

DEBUG = True
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "Xk9#mQ2vLp7$Rt4wZ8nB"
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///:memory:")
