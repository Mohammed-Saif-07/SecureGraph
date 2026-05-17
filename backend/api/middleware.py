from __future__ import annotations

import time

import redis
from fastapi import Header, HTTPException, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import settings


def require_api_key(x_api_key: str | None = Header(default=None)):
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing API key")
    return x_api_key


class RateLimitAndAuthMiddleware(BaseHTTPMiddleware):
    """JWT-aware Redis rate limiting for scans and LLM queries."""

    def __init__(self, app):
        super().__init__(app)
        self.redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health" or request.url.path.startswith("/api/auth") or request.url.path.startswith("/docs") or request.url.path.startswith("/openapi"):
            return await call_next(request)

        subject = request.client.host if request.client else "anonymous"
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            try:
                payload = jwt.decode(auth.removeprefix("Bearer ").strip(), settings.jwt_secret, algorithms=["HS256"])
                subject = payload.get("sub", subject)
            except JWTError:
                if settings.auth_required:
                    return JSONResponse({"detail": "Invalid bearer token"}, status_code=401)
        elif settings.auth_required:
            return JSONResponse({"detail": "Missing bearer token"}, status_code=401)

        if settings.rate_limit_enabled:
            limited = self._rate_limit(request.url.path, subject)
            if limited:
                return limited
        return await call_next(request)

    def _rate_limit(self, path: str, subject: str) -> JSONResponse | None:
        """Apply per-day user limits and return a 429 response when exceeded."""
        if path.startswith("/api/scans"):
            limit = settings.scan_rate_limit_per_day
            bucket = "scans"
        elif path.startswith("/api/llm"):
            limit = settings.query_rate_limit_per_day
            bucket = "queries"
        else:
            return None
        day = time.strftime("%Y%m%d")
        key = f"rate:{bucket}:{subject}:{day}"
        try:
            count = self.redis.incr(key)
            if count == 1:
                self.redis.expire(key, 24 * 60 * 60)
            if count > limit:
                return JSONResponse(
                    {"detail": "Too Many Requests", "limit": limit, "bucket": bucket},
                    status_code=429,
                    headers={"Retry-After": "86400"},
                )
        except redis.RedisError:
            return None
        return None
