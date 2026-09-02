import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from sdk.secure_fastapi import SecureFastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

app = SecureFastAPI(
    service_name="product-service",
    keycloak_url=os.getenv("KEYCLOAK_URL"),
    realm=os.getenv("KEYCLOAK_REALM"),
    client_id=os.getenv("PRODUCT_CLIENT_ID"),
    client_secret=os.getenv("PRODUCT_CLIENT_SECRET")
)

products_db: dict[int, dict] = {
    1: {"id": 1, "name": "MacBook Pro", "price": 25000.0, "stock": 100}
}
_counter = 1

def _next_id():
    global _counter
    _counter += 1
    return _counter

class ProductCreate(BaseModel):
    name: str
    price: float
    stock: int = 0

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "product-service"}

@app.post("/products", status_code=201)
async def create_product(product: ProductCreate, token=app.verify_request()):
    pid = _next_id()
    products_db[pid] = {"id": pid, **product.model_dump()}
    return products_db[pid]

@app.get("/products")
async def list_products(token=app.verify_request()):
    return list(products_db.values())

@app.get("/products/{product_id}")
async def get_product(product_id: int, token=app.verify_request()):
    if product_id not in products_db:
        raise HTTPException(status_code=404, detail="Produit non trouvé")
    return products_db[product_id]

@app.patch("/products/{product_id}/stock")
async def update_stock(product_id: int, quantity: int, token=app.verify_request()):
    if product_id not in products_db:
        raise HTTPException(status_code=404, detail="Produit non trouvé")
    product = products_db[product_id]
    if product["stock"] < quantity:
        raise HTTPException(status_code=409, detail=f"Stock insuffisant ({product['stock']} dispo, {quantity} demandé)")
    product["stock"] -= quantity
    print(f"[product-service] Stock mis à jour : -{quantity} → reste {product['stock']}")
    return product

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
