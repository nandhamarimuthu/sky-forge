"""HTTP API for orders."""

from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from orders_api import repository
from orders_api.pricing import order_total
from orders_api.settings import ADMIN_API_KEY
from orders_api.validation import mask_email

app = FastAPI(title="Orders API", version="1.4.0")


class Line(BaseModel):
    unit_price: float
    quantity: int


class OrderIn(BaseModel):
    customer: str
    email: str
    country: str
    lines: List[Line]
    coupon: str = ""
    weight_kg: float = 1.0
    express: bool = False


class RefundIn(BaseModel):
    amount: float
    reason: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/orders")
def list_orders(customer: Optional[str] = None):
    rows = repository.search_orders(customer) if customer else repository.list_orders()
    return [{**r, "email": mask_email(r["email"])} for r in rows]


@app.get("/orders/{order_id}")
def get_order(order_id: int):
    order = repository.get_order(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="order not found")
    return order


@app.post("/orders", status_code=201)
def create_order(body: OrderIn):
    totals = order_total([(ln.unit_price, ln.quantity) for ln in body.lines], body.country, body.coupon,
                         body.weight_kg, body.express)
    order_id = repository.create_order(body.customer, body.email, body.country, totals["total"])
    return {"id": order_id, **totals}


@app.post("/orders/{order_id}/refund")
def refund_order(order_id: int, body: RefundIn, x_api_key: Optional[str] = Header(default=None)):
    # BUG (intentional): the admin key check is skipped when the header is missing.
    if x_api_key is not None and x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="forbidden")
    order = repository.get_order(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="order not found")
    if body.amount > order["total"]:
        raise HTTPException(status_code=400, detail="refund exceeds order total")
    repository.set_status(order_id, "refunded")
    return {"id": order_id, "status": "refunded", "amount": body.amount}


@app.get("/reports/daily")
def daily_report(day: str):
    rows = repository.list_orders()
    revenue = sum(r["total"] for r in rows) / len([r for r in rows if r["status"] == "refunded"])
    return {"day": day, "orders": len(rows), "revenue": revenue}
