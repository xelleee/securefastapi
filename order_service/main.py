import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from sdk.secure_fastapi import SecureFastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import uvicorn

USER_SERVICE_URL = os.getenv("USER_SERVICE_URL")
PRODUCT_SERVICE_URL = os.getenv("PRODUCT_SERVICE_URL")

app = SecureFastAPI(
    service_name="order-service",
    keycloak_url=os.getenv("KEYCLOAK_URL"),
    realm=os.getenv("KEYCLOAK_REALM"),
    client_id=os.getenv("ORDER_CLIENT_ID"),
    client_secret=os.getenv("ORDER_CLIENT_SECRET")
)

orders_db: dict[int, dict] = {}
_counter = 0

def _next_id():
    global _counter
    _counter += 1
    return _counter

class OrderCreate(BaseModel):
    user_id: int
    product_id: int
    quantity: int = 1

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "order-service"}

@app.post("/orders", status_code=201)
async def create_order(order: OrderCreate):
    print(f"[order-service] Début du traitement de la commande {order.model_dump()}")

    print(f"[order-service] Appel 1/3 → User Service")
    r = await app.client.get(f"{USER_SERVICE_URL}/users/{order.user_id}")
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=f"User Service: {r.text}")
    user = r.json()
    print(f"[order-service] Client vérifié : {user['name']}")

    print(f"[order-service] Appel 2/3 → Product Service")
    r = await app.client.get(f"{PRODUCT_SERVICE_URL}/products/{order.product_id}")
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=f"Product Service: {r.text}")
    product = r.json()
    print(f"[order-service] Produit vérifié : {product['name']} — {product['price']}€")

    print(f"[order-service] Appel 3/3 → Product Service (Stock)")
    r = await app.client.patch(
        f"{PRODUCT_SERVICE_URL}/products/{order.product_id}/stock",
        params={"quantity": order.quantity},
    )
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.json().get("detail", "Stock insuffisant"))
    print(f"[order-service] Stock décrémenté de {order.quantity}")

    oid = _next_id()
    total = product["price"] * order.quantity
    new_order = {
        "id": oid,
        "user_id": order.user_id,
        "user_name": user["name"],
        "product_id": order.product_id,
        "product_name": product["name"],
        "quantity": order.quantity,
        "total_price": total,
        "status": "confirmed",
        "created_at": datetime.utcnow().isoformat(),
    }
    orders_db[oid] = new_order
    print(f"[order-service] Commande #{oid} créée — {total}€")
    return new_order

@app.get("/orders")
async def list_orders(token=app.verify_request()):
    return list(orders_db.values())

@app.get("/orders/{order_id}")
async def get_order(order_id: int, token=app.verify_request()):
    if order_id not in orders_db:
        raise HTTPException(status_code=404, detail="Commande non trouvée")
    return orders_db[order_id]

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
