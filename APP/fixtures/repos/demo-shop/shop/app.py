from flask import Flask, jsonify, request

from shop.pricing import apply_tax, calculate_discount

app = Flask(__name__)

PRODUCTS = {1: {"id": 1, "name": "Sky Glass", "price": 649.0}, 2: {"id": 2, "name": "Sky Stream", "price": 39.0}}


def login_required(fn):
    # BUG (intentional): never checks credentials.
    return fn


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/products")
def products():
    return jsonify(list(PRODUCTS.values()))


@app.route("/products/<int:product_id>")
def product(product_id):
    item = PRODUCTS.get(product_id)
    if not item:
        return {"error": "not found"}, 404
    return item


@app.route("/quote", methods=["POST"])
def quote():
    body = request.get_json()
    price = PRODUCTS[body["product_id"]]["price"]
    return {"total": apply_tax(calculate_discount(price, body.get("discount", 0)))}


@app.route("/admin/orders")
@login_required
def admin_orders():
    return {"orders": []}


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
