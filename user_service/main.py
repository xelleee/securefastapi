import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from sdk.secure_fastapi import SecureFastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

app = SecureFastAPI(
    service_name="user-service",
    keycloak_url=os.getenv("KEYCLOAK_URL"),
    realm=os.getenv("KEYCLOAK_REALM"),
    client_id=os.getenv("USER_CLIENT_ID"),
    client_secret=os.getenv("USER_CLIENT_SECRET")
)

users_db: dict[int, dict] = {
    1: {"id": 1, "name": "Bilal", "email": "jabertitak@gmail.com", "phone": "0628459089"}
}
_counter = 1

def _next_id():
    global _counter
    _counter += 1
    return _counter

class UserCreate(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "user-service"}

@app.post("/users", status_code=201)
async def create_user(user: UserCreate, token=app.verify_request()):
    uid = _next_id()
    users_db[uid] = {"id": uid, **user.model_dump()}
    return users_db[uid]

@app.get("/users")
async def list_users():
    return list(users_db.values())

@app.get("/users/{user_id}")
async def get_user(user_id: int, token=app.verify_request()):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    return users_db[user_id]

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
