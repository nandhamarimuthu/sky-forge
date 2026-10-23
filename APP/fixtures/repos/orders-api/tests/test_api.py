from fastapi.testclient import TestClient

from orders_api.main import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}
