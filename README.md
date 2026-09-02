# 🛡️ SecureFastAPI SDK

Building microservices with FastAPI usually requires writing the same boilerplate over and over: JWT validation, Machine-to-Machine (M2M) authentication, Prometheus metrics, structured logging, and distributed tracing.

**SecureFastAPI** is a custom SDK built to wrap all of these concerns into a single, clean interface. By replacing the standard `FastAPI()` instance with `SecureFastAPI()`, you get a production-ready microservice out of the box.

## Core Features Breakdown
SecureFastAPI doesn't just wrap FastAPI; it injects enterprise-grade microservice patterns natively.

### 1. JWKS Caching & Local Validation
Instead of calling Keycloak on every request, the SDK fetches Keycloak's public keys (JWKS) and caches them in memory (with a configurable TTL). Every incoming JWT is validated locally (signature, expiration, audience). If Keycloak rotates its keys, the SDK automatically detects the missing `kid` and silently refreshes the JWKS cache.

### 2. Smart Background Token Revocation
JWTs are stateless, meaning a revoked token (e.g., a banned user) remains mathematically valid until expiration. To solve this, the SDK performs background introspection:
* Known valid tokens are kept in a short-lived Whitelist (e.g., 60 seconds).
* Known invalid tokens are kept in a Blacklist (e.g., 15 minutes).
* If a token is not in cache, the SDK triggers a background, non-blocking HTTP call to Keycloak's `/userinfo` endpoint. If Keycloak rejects it, the token is instantly blacklisted. This guarantees real-time security without adding 150ms of latency to every user request.

### 3. Managed M2M HTTP Client (`app.client`)
Service-to-service calls require Machine-to-Machine (Client Credentials) tokens. Using `app.client` handles the entire lifecycle:
* Requests an M2M token from Keycloak using the service's `client_id` and `client_secret`.
* Caches the token in memory.
* Automatically and preemptively renews the token 30 seconds before it expires (using `asyncio.Lock` to prevent concurrent renewal races).
* Auto-injects the `Authorization: Bearer` header into all outbound requests.

### 4. Distributed Tracing & Correlation IDs
* The `CorrelationIdMiddleware` captures the `X-Request-ID` from incoming requests (or generates a UUID4 if missing) and stores it in a Python ContextVar.
* The custom JSON logger automatically injects this ID into every log line.
* The internal client automatically forwards this header in outbound requests.
* **Result:** You can trace a single user action seamlessly across `order-service`, `product-service`, and `user-service` in Loki/Grafana.

### 5. Automated Observability (Metrics, Logs, Health)
* **Prometheus:** Automatically exposes a `/metrics` endpoint. Tracks request duration histograms, total requests, and actively running requests (`http_requests_inprogress`).
* **Structured Logging:** Overrides default Uvicorn/FastAPI loggers to output machine-readable JSON logs, perfectly formatted for Loki ingestion.
* **Healthchecks:** Auto-injects `/health` (Liveness) and `/ready` endpoints to verify the service status and its connection to Keycloak.

---

## 1. Infrastructure Management (Admin Dashboard)

Managing Keycloak manually (creating clients, generating secrets, configuring scopes and audiences) can be tedious and error-prone. **To solve this, we provide a centralized Admin Dashboard.**

The Admin Dashboard acts as the control center for your microservices' identity and access management. It provides a clean, visual interface to fully automate Keycloak configurations.

### What You Can Do
* **Register Microservices:** Create new M2M clients (e.g., `payment-service`) and retrieve their `CLIENT_SECRET` in one click.
* **Automated Provisioning:** Global scopes and OIDC audience mappers are instantly generated and configured the moment a service is created.
* **Manage Permissions (Scopes):** Visually link or unlink scopes using a dropdown interface to control exactly which APIs a service is allowed to consume.
* **State Management:** Toggle microservices on or off (enable/disable) in real-time.
* **Cache Management:** Trigger a remote cache refresh on a specific microservice to invalidate its in-memory JWKS and tokens immediately, without waiting for the standard TTL to expire.

### How to Use It
1. Ensure Keycloak is running.
2. Open the Admin Dashboard and log in using your Keycloak `admin` credentials.
3. Provision your new service via the interface.
4. Copy the generated **Client Secret** and add it to your microservice's `.env` file.

*(Note: Manual configuration is still possible via the Keycloak UI, but the Admin Dashboard guarantees standard compliance with our SDK's scope and audience expectations).*

---

## 2. Installation & Environment Setup
Ensure the SDK is accessible in your project structure, then define the following environment variables in your `.env` file:

```bash
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=microservices
CLIENT_ID=order-service
CLIENT_SECRET=your-client-secret
LOKI_URL=http://localhost:3100
```

---

## 3. Usage Guide

### A. Initializing the Service
Replace `FastAPI()` with `SecureFastAPI`.

```python
from sdk.secure_fastapi import SecureFastAPI

app = SecureFastAPI(
    service_name="order-service",
    keycloak_url="http://localhost:8080",
    realm="microservices",
    client_id="order-service",
    client_secret="secret"
)
```

### B. Protecting Endpoints
Inject `app.verify_request()` to secure routes.

```python
@app.get("/orders/me")
async def get_my_orders(token = app.verify_request()):
    return {"user_id": token.get("sub")}
```

### C. Service-to-Service (M2M) Calls
Use `app.client` to automatically manage and inject M2M tokens.

```python
@app.post("/orders")
async def create_order():
    response = await app.client.get("http://product-service:8002/products")
    return response.json()
```

### D. Structured Logging
Output JSON logs with auto-injected Trace IDs.

```python
from sdk.secure_fastapi import setup_logger

logger = setup_logger("order-service")

@app.post("/orders")
async def create_order():
    logger.info("order_creation_started", extra={"amount": 50})
    return {"status": "created"}
```

---

