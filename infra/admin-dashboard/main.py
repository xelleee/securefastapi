from fastapi import FastAPI, Request
from fastapi import Form, Response, HTTPException, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
import httpx
from typing import Optional

app = FastAPI(title="Admin Dashboard API")

import os
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM_NAME = os.getenv("KEYCLOAK_REALM", "master")
ADMIN_REALM = "master"

# ==========================================

import os

@app.get("/")
async def serve_ui():
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
    with open(template_path, 'r', encoding='utf-8') as f:
        html = f.read()
    return HTMLResponse(content=html, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

# AUTHENTICATION & SECURITY
# ==========================================

async def get_admin_token(request: Request) -> str:
    token = request.cookies.get("admin_token")
    if not token:
        raise HTTPException(status_code=401, detail="Non authentifié. Veuillez vous connecter.")
    return token



@app.post("/api/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):

    with open('login_attempts.log', 'a') as logf:
        logf.write(f"Login attempt: {username}\n")

    """Authenticate administrator and set session cookie."""
    async with httpx.AsyncClient() as client:
        res = await client.post(f"{KEYCLOAK_URL}/realms/{ADMIN_REALM}/protocol/openid-connect/token", data={
            "client_id": "admin-cli",
            "username": username,
            "password": password,
            "grant_type": "password"
        })
        
        if res.status_code != 200:
            raise HTTPException(status_code=401, detail="Identifiants invalides")
            
        token = res.json()["access_token"]
        response.set_cookie(key="admin_token", value=token, httponly=True, max_age=3600)
        return {"message": "Connexion réussie"}

@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("admin_token")
    return {"message": "Déconnecté"}

# ==========================================
# SERVICES MANAGEMENT (M2M CLIENTS)
# ==========================================

@app.get("/api/services")
async def list_services(token: str = Depends(get_admin_token)):
    """List all active backend microservices."""
    async with httpx.AsyncClient() as client:
        res = await client.get(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients",
            headers={"Authorization": f"Bearer {token}"}
        )
        # Ignore Keycloak default internal clients
        default_clients = ["account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console", "master-realm"]
        clients = [c for c in res.json() if c["clientId"] not in default_clients and not c["clientId"].startswith("system")]
        return clients

class ServiceCreateRequest(BaseModel):
    client_id: str
    description: str
    client_secret: str
    root_url: str = ""

@app.post("/api/services")
async def create_service(req: ServiceCreateRequest, token: str = Depends(get_admin_token)):
    """Register a new M2M microservice client in Keycloak."""
    payload = {
        "clientId": req.client_id,
        "description": req.description,
        "enabled": True,
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "protocol": "openid-connect",
        "secret": req.client_secret
    }
    if req.root_url:
        payload["rootUrl"] = req.root_url
    
    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients",
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        if res.status_code != 201:
            raise HTTPException(status_code=res.status_code, detail="Erreur lors de la création du service")
            
        client_uuid = res.headers["Location"].split("/")[-1]
        scope_name = req.client_id
        print(f"[AUTO-SCOPE] Service créé: {req.client_id} (uuid={client_uuid}). Création du scope '{scope_name}'...")
        
        # Check if scope already exists
        scopes_res = await client.get(f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes", headers={"Authorization": f"Bearer {token}"})
        if scopes_res.status_code == 200:
            scopes = scopes_res.json()
            scope_uuid = next((s["id"] for s in scopes if s["name"] == scope_name), None)
            
            # Create scope if it does not exist
            if not scope_uuid:
                print(f"[AUTO-SCOPE] Creating missing scope: {scope_name}")
                create_scope_res = await client.post(
                    f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes",
                    json={"name": scope_name, "protocol": "openid-connect"},
                    headers={"Authorization": f"Bearer {token}"}
                )
                print(f"[AUTO-SCOPE] Scope creation status: {create_scope_res.status_code}")
                if create_scope_res.status_code == 201:
                    scope_uuid = create_scope_res.headers["Location"].split("/")[-1]
                    print(f"[AUTO-SCOPE] Scope created successfully. UUID: {scope_uuid}")
                    
                    # Add Audience Mapper to the newly created scope
                    mapper_payload = {
                        "name": f"audience-mapping-{req.client_id}",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.client.audience": req.client_id,
                            "id.token.claim": "false",
                            "access.token.claim": "true"
                        }
                    }
                    res_mapper = await client.post(
                        f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes/{scope_uuid}/protocol-mappers/models",
                        json=mapper_payload,
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    if res_mapper.status_code == 201:
                        print(f"[AUTO-SCOPE] Audience mapper added for {req.client_id}")
                    else:
                        print(f"[AUTO-SCOPE] Error adding audience mapper: {res_mapper.text}")
                else:
                    print(f"[AUTO-SCOPE] Error creating scope: {create_scope_res.text}")
            else:
                print(f"[AUTO-SCOPE] Scope already exists. UUID: {scope_uuid}")
            
            # Link the scope to the created service client
            if scope_uuid:
                scope_data_res = await client.get(f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes/{scope_uuid}", headers={"Authorization": f"Bearer {token}"})
                if scope_data_res.status_code == 200:
                    scope_data = scope_data_res.json()
                    assign_res = await client.put(
                        f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients/{client_uuid}/default-client-scopes/{scope_uuid}",
                        json=scope_data,
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    print(f"[AUTO-SCOPE] Assignation scope->service status: {assign_res.status_code}")
        else:
            print(f"[AUTO-SCOPE] ERREUR: impossible de lister les scopes (status={scopes_res.status_code})")
                    
        return {"message": f"Service et Scope '{scope_name}' créés avec succès"}

class ToggleRequest(BaseModel):
    enabled: bool

@app.put("/api/services/{client_uuid}/toggle")
async def toggle_service(client_uuid: str, req: ToggleRequest, token: str = Depends(get_admin_token)):
    """Toggle the enabled status of a microservice."""
    async with httpx.AsyncClient() as client:
        res = await client.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients/{client_uuid}",
            json={"enabled": req.enabled},
            headers={"Authorization": f"Bearer {token}"}
        )
        return {"message": "Statut du service mis à jour"}

@app.delete("/api/services/{client_uuid}")
async def delete_service(client_uuid: str, token: str = Depends(get_admin_token)):
    """Permanently delete a microservice client."""
    async with httpx.AsyncClient() as client:
        await client.delete(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients/{client_uuid}",
            headers={"Authorization": f"Bearer {token}"}
        )
        return {"message": "Service supprimé"}

# ==========================================
# ACCESS & SCOPES MANAGEMENT
# ==========================================

class ScopeActionRequest(BaseModel):
    scope_name: str

@app.post("/api/services/{client_uuid}/scopes")
async def add_scope(client_uuid: str, req: ScopeActionRequest, token: str = Depends(get_admin_token)):
    """Attach a client scope to a microservice."""
    async with httpx.AsyncClient() as client:
        # Retrieve scope ID by name or create it if missing
        scopes_res = await client.get(f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes", headers={"Authorization": f"Bearer {token}"})
        scopes = scopes_res.json()
        
        scope_uuid = next((s["id"] for s in scopes if s["name"] == req.scope_name), None)
        
        if not scope_uuid:
            create_res = await client.post(
                f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes",
                json={"name": req.scope_name, "protocol": "openid-connect"},
                headers={"Authorization": f"Bearer {token}"}
            )
            scope_uuid = create_res.headers["Location"].split("/")[-1]
            
        # Fetch scope payload required for linking
        scope_data_res = await client.get(f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes/{scope_uuid}", headers={"Authorization": f"Bearer {token}"})
        scope_data = scope_data_res.json()

        # Link scope to client
        await client.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients/{client_uuid}/default-client-scopes/{scope_uuid}",
            json=scope_data,
            headers={"Authorization": f"Bearer {token}"}
        )
        return {"message": f"Scope {req.scope_name} ajouté au service"}

@app.delete("/api/services/{client_uuid}/scopes")
async def remove_scope(client_uuid: str, req: ScopeActionRequest, token: str = Depends(get_admin_token)):
    """Detach a client scope from a microservice."""
    async with httpx.AsyncClient() as client:
        # Retrieve scope ID by name
        scopes_res = await client.get(f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes", headers={"Authorization": f"Bearer {token}"})
        scopes = scopes_res.json()
        
        scope_uuid = next((s["id"] for s in scopes if s["name"] == req.scope_name), None)
        
        if not scope_uuid:
            raise HTTPException(status_code=404, detail="Scope introuvable.")
            
        await client.delete(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients/{client_uuid}/default-client-scopes/{scope_uuid}",
            headers={"Authorization": f"Bearer {token}"}
        )
        return {"message": "Scope retiré"}


# ==========================================
# GLOBAL SCOPES & AUDIENCES
# ==========================================

@app.get("/api/global-scopes")
async def list_global_scopes(token: str = Depends(get_admin_token)):
    """List all custom global client scopes in the realm."""
    async with httpx.AsyncClient() as client:
        res = await client.get(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes",
            headers={"Authorization": f"Bearer {token}"}
        )
        scopes = res.json()
        # Ignore Keycloak default internal scopes
        default_scopes = ["acr", "roles", "profile", "email", "address", "phone", "microprofile-jwt", "offline_access", "role_list", "organization", "web-origins", "saml_organization", "basic", "AuthnContextClassRef", "service_account"]
        return [s for s in scopes if not s["name"].startswith("web-origins") and s["name"] not in default_scopes]

class GlobalScopeCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    audience: Optional[str] = ""

@app.post("/api/global-scopes")
async def create_global_scope(req: GlobalScopeCreateRequest, token: str = Depends(get_admin_token)):
    """Create a global client scope and optional audience mapper."""
    async with httpx.AsyncClient() as client:
        # Create the Client Scope
        scope_payload = {
            "name": req.name,
            "description": req.description,
            "protocol": "openid-connect"
        }
        res = await client.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes",
            json=scope_payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        if res.status_code != 201:
            raise HTTPException(status_code=res.status_code, detail="Erreur lors de la crǸation du scope.")
            
        # Extract scope ID from response Location header
        scope_uuid = res.headers["Location"].split("/")[-1]
        
        # Add Audience Mapper if audience claim is provided
        if req.audience:
            mapper_payload = {
                "name": f"audience-mapping-{req.audience}",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": req.audience,
                    "id.token.claim": "false",
                    "access.token.claim": "true"
                }
            }
            res_mapper = await client.post(
                f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes/{scope_uuid}/protocol-mappers/models",
                json=mapper_payload,
                headers={"Authorization": f"Bearer {token}"}
            )
            if res_mapper.status_code != 201:
                return {"message": "Scope crǸǸ, mais erreur lors de l'ajout de l'audience."}
                
        return {"message": "Scope et Audience crǸǸs avec succs !"}


@app.delete("/api/global-scopes/{scope_uuid}")
async def delete_global_scope(scope_uuid: str, token: str = Depends(get_admin_token)):
    """Permanently delete a global client scope."""
    async with httpx.AsyncClient() as client:
        res = await client.delete(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/client-scopes/{scope_uuid}",
            headers={"Authorization": f"Bearer {token}"}
        )
        if res.status_code == 204:
            return {"message": "Scope supprimé"}
        else:
            raise HTTPException(status_code=res.status_code, detail="Erreur lors de la suppression.")

# ==========================================
# SERVICE CACHE MANAGEMENT
# ==========================================

@app.post("/api/services/{client_uuid}/refresh")
async def refresh_service_cache(client_uuid: str, token: str = Depends(get_admin_token)):
    """Trigger cache refresh on a specific microservice via its Root URL."""
    async with httpx.AsyncClient() as client:
        # Fetch client configuration to extract Root URL
        client_res = await client.get(
            f"{KEYCLOAK_URL}/admin/realms/{REALM_NAME}/clients/{client_uuid}",
            headers={"Authorization": f"Bearer {token}"}
        )
        if client_res.status_code != 200:
            raise HTTPException(status_code=404, detail="Service introuvable dans Keycloak")
            
        client_data = client_res.json()
        root_url = client_data.get("rootUrl")
        
        if not root_url:
            raise HTTPException(status_code=400, detail="Ce service n'a pas de Root URL configuré. Impossible de vider son cache.")
            
        # Send clear-cache request to the service via Root URL
        try:
            res = await client.post(f"{root_url.rstrip('/')}/refresh", timeout=3.0)
            if res.status_code == 200:
                return {"message": f"Cache vidé avec succès pour {client_data['clientId']}"}
            else:
                raise HTTPException(status_code=res.status_code, detail=f"Le service a renvoyé une erreur {res.status_code}")
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail=f"Le service {client_data['clientId']} ({root_url}) est injoignable.")
