from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
from queue import Queue
from typing import Any


import httpx
import jwt
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)
from starlette.middleware.base import BaseHTTPMiddleware

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)


class JSONFormatter(logging.Formatter):
    """Formats log records as structured JSON for Loki or other monitoring systems."""

    _RESERVED = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        cid = correlation_id_var.get()
        if cid:
            log_data["correlation_id"] = cid
        for key, value in record.__dict__.items():
            if key not in self._RESERVED:
                try:
                    json.dumps(value)
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data, ensure_ascii=False)


def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Creates a JSON logger. Automatically forwards logs to Loki if LOKI_URL is configured."""
    import os

    logger = logging.getLogger(name)
    has_json_handler = any(
        isinstance(h, logging.StreamHandler) and isinstance(h.formatter, JSONFormatter)
        for h in logger.handlers
    )
    if not has_json_handler:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    loki_url = os.getenv("LOKI_URL")
    if loki_url:
        try:
            import logging_loki

            logging_loki.emitter.LokiEmitter.level_tag = "level"
            service_tag = name.replace("secure_fastapi.", "")

            # LokiQueueHandler sends logs in a separate thread for zero latency impact.
            loki_handler = logging_loki.LokiQueueHandler(
                Queue(-1),
                url=loki_url.rstrip("/") + "/loki/api/v1/push",
                tags={"service": service_tag},
                version="1",
            )
            loki_handler.setFormatter(JSONFormatter())
            logger.addHandler(loki_handler)
        except ImportError:
            pass

    logger.setLevel(level)
    logger.propagate = False
    return logger


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Injects X-Request-ID into every request to trace correlation across microservices."""

    HEADER_NAME = "X-Request-ID"

    async def dispatch(self, request: Request, call_next):
        cid = request.headers.get(self.HEADER_NAME) or str(uuid.uuid4())
        request.state.correlation_id = cid
        token = correlation_id_var.set(cid)
        try:
            response = await call_next(request)
            response.headers[self.HEADER_NAME] = cid
            return response
        finally:
            correlation_id_var.reset(token)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Automatically logs each HTTP request duration and status."""

    def __init__(self, app, service_name: str, logger: logging.Logger):
        super().__init__(app)
        self.service_name = service_name
        self.logger = logger

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        start_time = time.time()
        try:
            response = await call_next(request)
            duration_ms = round((time.time() - start_time) * 1000, 2)
            self.logger.info(
                "request_completed",
                extra={
                    "event": "request_completed",
                    "service": self.service_name,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "client_ip": client_ip,
                },
            )
            return response
        except Exception as e:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            self.logger.error(
                "request_failed",
                extra={
                    "event": "request_failed",
                    "service": self.service_name,
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                    "client_ip": client_ip,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise


class SecureFastAPI(FastAPI):
    """
    Extension de FastAPI avec la sécurité intégrée :
    validation JWT, révocation en temps réel, tokens M2M et logging automatique.
    """

    DEFAULT_HTTP_TIMEOUT = 10.0  # Timeout (seconds) for generic HTTP calls
    DEFAULT_JWKS_FETCH_TIMEOUT = 5.0  # Timeout used when fetching JWKS or UserInfo
    DEFAULT_JWKS_CACHE_TTL = 600  # TTL for JWKS cache (seconds)
    DEFAULT_INTROSPECTION_CACHE_TTL = 60  # Whitelist TTL (1 min)
    DEFAULT_BLACKLIST_CACHE_TTL = 900  # Blacklist TTL (15 min)

    def __init__(
        self,
        service_name: str,
        keycloak_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        audience: str | None = None,
        jwks_cache_ttl: int = DEFAULT_JWKS_CACHE_TTL,
        enable_introspection: bool = True,
        user_agent: str = "Mozilla/5.0",
        *args,
        **kwargs,
    ):
        """Configures Keycloak connection, initializes caches, and registers middlewares."""
        kwargs.setdefault("lifespan", self._build_lifespan())
        super().__init__(*args, **kwargs)

        self.service_name = service_name
        self.keycloak_url = keycloak_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience or client_id
        self.jwks_cache_ttl = jwks_cache_ttl
        self.user_agent = user_agent

        self.expected_issuer = f"{self.keycloak_url}/realms/{self.realm}"
        self.jwks_url = f"{self.expected_issuer}/protocol/openid-connect/certs"
        self.token_url = f"{self.expected_issuer}/protocol/openid-connect/token"

        self.introspection_enabled = enable_introspection

        self._jwks_dict_cache: dict[str, Any] = {}
        self._jwks_cache_loaded_at: float = 0.0
        # Locks must be initialized here to be available immediately.
        self._jwks_lock = asyncio.Lock()
        self._token_lock = asyncio.Lock()
        self._revocation_lock = asyncio.Lock()

        self._service_token: str | None = None
        self._service_token_expires_at: float = 0.0

        # Revocation cache: whitelist for valid tokens, blacklist for revoked ones.
        self._whitelist_cache: dict[str, float] = {}
        self._blacklist_cache: dict[str, float] = {}
        self._last_cache_cleanup: float = 0.0
        self._pending_revalidations: set[str] = set()

        self._http_client: httpx.AsyncClient | None = None

        self.logger = setup_logger(f"secure_fastapi.{service_name}")

        self.client: SecureHttpClient | None = None

        self.add_middleware(
            AuditLogMiddleware, service_name=service_name, logger=self.logger
        )
        self.add_middleware(CorrelationIdMiddleware)
        self.add_middleware(
            CORSMiddleware,
            allow_origins=[],
            allow_origin_regex=(
                r"^https://([a-zA-Z0-9-]+\.)*(experio\.ma|experioservice\.ma)$"
            ),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
        )

        self._setup_health_endpoints()
        self._setup_prometheus()

    def _setup_prometheus(self) -> None:
        """Exposes /metrics endpoint for Prometheus scraping."""
        try:
            from prometheus_fastapi_instrumentator import Instrumentator

            Instrumentator(
                should_instrument_requests_inprogress=True,
                inprogress_name="http_requests_inprogress",
                inprogress_labels=True,
            ).instrument(self).expose(self, endpoint="/metrics")
        except ImportError:
            pass

    def _build_lifespan(self):
        """Manages application lifecycle: initializes HTTP clients, pre-warms JWKS, and handles graceful shutdown."""

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            # Locks are already created in __init__; only HTTP clients are initialized here.
            self._http_client = httpx.AsyncClient(timeout=self.DEFAULT_HTTP_TIMEOUT)
            self.client = SecureHttpClient(api=self, timeout=self.DEFAULT_HTTP_TIMEOUT)

            self.logger.info(
                "service_starting",
                extra={"event": "service_starting", "service": self.service_name},
            )

            try:
                await self.sign_token()
                self.logger.info("warmup_token_ok", extra={"event": "warmup_token_ok"})
            except Exception as e:
                self.logger.warning(
                    "warmup_token_failed",
                    extra={"event": "warmup_token_failed", "error": str(e)},
                )

            try:
                await self._refresh_jwks()
                self.logger.info("warmup_jwks_ok", extra={"event": "warmup_jwks_ok"})
            except Exception as e:
                self.logger.warning(
                    "warmup_jwks_failed",
                    extra={"event": "warmup_jwks_failed", "error": str(e)},
                )

            self.logger.info(
                "service_ready",
                extra={"event": "service_ready", "service": self.service_name},
            )

            yield

            self.logger.info(
                "service_stopping",
                extra={"event": "service_stopping", "service": self.service_name},
            )
            try:
                if self._http_client:
                    await self._http_client.aclose()
                if self.client:
                    await self.client.aclose()
            except Exception as e:
                self.logger.warning(
                    "http_client_close_failed",
                    extra={"event": "http_client_close_failed", "error": str(e)},
                )
            self.logger.info(
                "service_stopped",
                extra={"event": "service_stopped", "service": self.service_name},
            )

        return lifespan

    def _setup_health_endpoints(self) -> None:
        """Injects /health, /ready, and /refresh utility endpoints."""

        @self.get("/health", include_in_schema=False)
        async def health():
            return {"status": "ok", "service": self.service_name}

        @self.get("/ready", include_in_schema=False)
        async def ready():
            checks: dict[str, str] = {}
            healthy = True

            try:
                if self._is_jwks_cache_expired or not self._jwks_dict_cache:
                    await self._refresh_jwks()
                checks["jwks"] = "ok"
            except Exception as e:
                checks["jwks"] = f"error: {e}"
                healthy = False

            checks["service_token"] = (
                "ok"
                if self._service_token and time.time() < self._service_token_expires_at
                else "not_cached"
            )

            return JSONResponse(
                status_code=200 if healthy else 503,
                content={
                    "status": "ok" if healthy else "degraded",
                    "service": self.service_name,
                    "checks": checks,
                },
            )

        @self.post("/refresh", include_in_schema=False)
        async def refresh_cache():
            """Clears revocation caches. Call this endpoint after updating permissions in Keycloak."""
            async with self._revocation_lock:
                cleared = len(self._whitelist_cache) + len(self._blacklist_cache)
                self._whitelist_cache.clear()
                self._blacklist_cache.clear()

            # Delete the M2M token to force a regeneration containing the new scopes.
            # This ensures outbound requests use updated permissions immediately.
            async with self._token_lock:
                self._service_token = None
                self._service_token_expires_at = 0

            self.logger.info(
                "cache_refreshed",
                extra={
                    "event": "cache_refreshed",
                    "service": self.service_name,
                    "entries_cleared": cleared,
                },
            )
            return {"message": "Cache vidé"}

    @property
    def _is_jwks_cache_expired(self) -> bool:
        """Returns True if the JWKS cache has expired."""
        if self._jwks_cache_loaded_at == 0:
            return True
        return (time.time() - self._jwks_cache_loaded_at) > self.jwks_cache_ttl

    async def _refresh_jwks(self) -> None:
        """Fetches and caches JWKS public keys from Keycloak."""
        async with self._jwks_lock:
            if not self._is_jwks_cache_expired:
                return

            self.logger.info(
                "jwks_refresh_start",
                extra={"event": "jwks_refresh_start", "url": self.jwks_url},
            )
            try:
                async with httpx.AsyncClient(
                    timeout=self.DEFAULT_JWKS_FETCH_TIMEOUT
                ) as client:
                    resp = await client.get(
                        self.jwks_url,
                        headers={"User-Agent": self.user_agent},
                    )
                    resp.raise_for_status()
                    new_cache: dict[str, Any] = {}
                    for jwk in resp.json().get("keys", []):
                        if "kid" in jwk:
                            new_cache[jwk["kid"]] = jwk
                    self._jwks_dict_cache = new_cache
                    self._jwks_cache_loaded_at = time.time()
                    self.logger.info(
                        "jwks_refresh_ok",
                        extra={"event": "jwks_refresh_ok", "key_count": len(new_cache)},
                    )
            except Exception as e:
                self.logger.error(
                    "jwks_refresh_failed",
                    extra={"event": "jwks_refresh_failed", "error": str(e)},
                    exc_info=True,
                )
                raise

    async def sign_token(self) -> str:
        """Returns the M2M Client Credentials token. Automatically renews it before expiration."""
        # Token is still valid; skip Keycloak request.
        if self._service_token and time.time() < (self._service_token_expires_at - 30):
            return self._service_token

        async with self._token_lock:
            # Double-check after acquiring lock: another coroutine might have already renewed the token.
            now = time.time()
            if self._service_token and now < (self._service_token_expires_at - 30):
                return self._service_token

        self.logger.info(
            "service_token_request", extra={"event": "service_token_request"}
        )
        try:
            response = await self._http_client.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    # Required to call /userinfo for revocation checks
                    "scope": "openid",
                },
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (400, 401, 403):
                self.logger.error(
                    "service_disabled_in_keycloak",
                    extra={"event": "service_disabled_in_keycloak"},
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Sécurité : Le microservice '{self.service_name}' "
                        "a été désactivé par l'administrateur Keycloak."
                    ),
                )
            raise
        data = response.json()
        self._service_token = data["access_token"]
        self._service_token_expires_at = now + data.get("expires_in", 900)
        self.logger.info(
            "service_token_obtained",
            extra={
                "event": "service_token_obtained",
                "expires_in": data.get("expires_in", 900),
            },
        )
        return self._service_token

    async def _check_revocation(
        self, token: str, background_tasks: Any | None = None
    ) -> bool:
        """
        Verify if the token revoked by cache or Keycloak background .
        Pattern Stale-While-Revalidate : Respond by  cache and Revalidate the token.
        """
        if not self.introspection_enabled:
            return True
        now = time.time()

        # Read cache under lock (takes < 1ms).
        async with self._revocation_lock:
            if now - self._last_cache_cleanup > 300:
                self._whitelist_cache = {
                    k: v for k, v in self._whitelist_cache.items() if v > now
                }
                self._blacklist_cache = {
                    k: v for k, v in self._blacklist_cache.items() if v > now
                }
                self._last_cache_cleanup = now

            bl_exp = self._blacklist_cache.get(token)
            in_blacklist = bool(bl_exp and bl_exp > now)

            wl_exp = self._whitelist_cache.get(token)
            in_whitelist = bool(wl_exp and wl_exp > now)
        # Lock released here - network calls should always happen outside the lock.

        # Blacklisted token: re-verify synchronously in case it was reactivated.
        if in_blacklist:
            return await self._sync_introspect(token, now)

        # Whitelisted token: authorize immediately and re-validate in background.
        if in_whitelist:
            if background_tasks:
                background_tasks.add_task(self._background_introspect, token)
            else:
                asyncio.create_task(self._background_introspect(token))
            return True

        # First time seeing this token: synchronous verification required.
        return await self._sync_introspect(token, now)

    async def _background_introspect(self, token: str) -> None:
        """Revalidates token with Keycloak in the background without blocking the HTTP response."""
        # Prevents duplicate Keycloak calls if multiple requests arrive simultaneously.
        async with self._revocation_lock:
            if token in self._pending_revalidations:
                return  # Another coroutine is already verifying this token.
            self._pending_revalidations.add(token)
        try:
            userinfo_url = (
                f"{self.keycloak_url}/realms/{self.realm}"
                "/protocol/openid-connect/userinfo"
            )
            response = await self._http_client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.DEFAULT_JWKS_FETCH_TIMEOUT,
            )
            now = time.time()
            async with self._revocation_lock:
                if response.status_code == 200:
                    # Token active -> cache to whitelist.
                    self._blacklist_cache.pop(token, None)
                    self._whitelist_cache[token] = (
                        now + self.DEFAULT_INTROSPECTION_CACHE_TTL
                    )
                else:
                    # Token revoked -> cache to blacklist.
                    self._whitelist_cache.pop(token, None)
                    self._blacklist_cache[token] = (
                        now + self.DEFAULT_BLACKLIST_CACHE_TTL
                    )
                    self.logger.info(
                        "token_revoked_realtime",
                        extra={"event": "token_revoked_realtime"},
                    )
        except Exception:
            pass  # Silent failure: do not impact the ongoing request.
        finally:
            async with self._revocation_lock:
                self._pending_revalidations.discard(token)

    async def _sync_introspect(self, token: str, now: float) -> bool:
        """Verifies the token synchronously with Keycloak (used for cache miss or blacklist)."""
        userinfo_url = (
            f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/userinfo"
        )
        try:
            response = await self._http_client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.DEFAULT_JWKS_FETCH_TIMEOUT,
            )
            is_active = response.status_code == 200
            if is_active:
                self._blacklist_cache.pop(token, None)
                self._whitelist_cache[token] = (
                    now + self.DEFAULT_INTROSPECTION_CACHE_TTL
                )
            else:
                self._whitelist_cache.pop(token, None)
                self._blacklist_cache[token] = now + self.DEFAULT_BLACKLIST_CACHE_TTL
                self.logger.info(
                    "token_revoked_by_userinfo",
                    extra={"event": "token_revoked_by_userinfo"},
                )
            return is_active
        except Exception as e:
            self.logger.error(
                "revocation_check_error",
                extra={"event": "revocation_check_error", "error": str(e)},
            )
            # Reject access on network error for security.
            return False



    async def verify_token(
        self,
        token: str,
        background_tasks: Any | None = None,
    ) -> dict[str, Any]:
        """Validates JWT signature, expiration, and revocation status. Returns payload if valid."""
        try:
            unverified_header = jwt.get_unverified_header(token)
        except DecodeError as e:
            self.logger.warning(
                "jwt_decode_error", extra={"event": "jwt_decode_error", "error": str(e)}
            )
            raise HTTPException(status_code=401, detail="Invalid Token")

        kid = unverified_header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Invalid Token")

        if self._is_jwks_cache_expired or kid not in self._jwks_dict_cache:
            await self._refresh_jwks()

        if kid not in self._jwks_dict_cache:
            self.logger.warning(
                "jwks_kid_not_found", extra={"event": "jwks_kid_not_found", "kid": kid}
            )
            raise HTTPException(status_code=401, detail="Invalid Token")

        public_key = jwt.PyJWK(self._jwks_dict_cache[kid]).key

        decode_kwargs: dict[str, Any] = {
            "algorithms": ["RS256"],
            "leeway": 30,
            "issuer": self.expected_issuer,
            "options": {
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_aud": bool(self.audience),
                "require": ["exp", "iat"],
            },
        }
        if self.audience:
            decode_kwargs["audience"] = self.audience

        try:
            payload = jwt.decode(token, key=public_key, **decode_kwargs)

        except ExpiredSignatureError:
            self.logger.warning("jwt_expired", extra={"event": "jwt_expired"})
            raise HTTPException(status_code=401, detail="Invalid Token")

        except InvalidSignatureError:
            self.logger.critical(
                "jwt_invalid_signature",
                extra={
                    "event": "jwt_invalid_signature",
                    "severity": "critical",
                    "kid": kid,
                },
            )
            raise HTTPException(status_code=401, detail="Invalid Token")

        except InvalidAudienceError:
            self.logger.warning(
                "jwt_invalid_audience",
                extra={"event": "jwt_invalid_audience", "expected": self.audience},
            )
            raise HTTPException(status_code=401, detail="Invalid Token")

        except InvalidIssuerError:
            self.logger.warning(
                "jwt_invalid_issuer",
                extra={"event": "jwt_invalid_issuer", "expected": self.expected_issuer},
            )
            raise HTTPException(status_code=401, detail="Invalid Token")

        except InvalidTokenError as e:
            self.logger.warning(
                "jwt_invalid", extra={"event": "jwt_invalid", "error": str(e)}
            )
            raise HTTPException(status_code=401, detail="Invalid Token")

        if not await self._check_revocation(token, background_tasks=background_tasks):
            self.logger.warning(
                "token_revoked", extra={"event": "token_revoked", "kid": kid}
            )
            raise HTTPException(status_code=401, detail="Microservice Disabled")

        return payload

    def verify_request(self):
        """FastAPI dependency for protected routes. Validates JWT and extracts payload."""

        async def dependency(request: Request, background_tasks: BackgroundTasks):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="Unauthorized: Missing Token (M2M Required)",
                )
            token = auth_header[len("Bearer ") :]
            return await self.verify_token(
                token,
                background_tasks=background_tasks,
            )

        return Depends(dependency)


class SecureHttpClient(httpx.AsyncClient):
    """HTTP Client that auto-injects M2M token and X-Request-ID into outbound requests."""

    def __init__(self, api: SecureFastAPI, **kwargs):
        """Binds the client to the SecureFastAPI instance to retrieve M2M tokens."""
        super().__init__(**kwargs)
        self.api = api
        self.logger = setup_logger(f"secure_http_client.{api.service_name}")

    async def request(self, method, url, **kwargs):
        """Injects M2M token and correlation ID before making HTTP requests."""
        token = await self.api.sign_token()
        headers = kwargs.pop("headers", None) or {}
        headers["Authorization"] = f"Bearer {token}"
        cid = correlation_id_var.get()
        if cid:
            headers["X-Request-ID"] = cid
        kwargs["headers"] = headers
        return await super().request(method, url, **kwargs)
