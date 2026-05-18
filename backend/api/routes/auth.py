from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from core.config import settings
from core.sql_db import Organization, Project, User, get_db

router = APIRouter()
HASH_ITERATIONS = 260_000


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["founder@example.com"])
    password: str = Field(..., min_length=8, examples=["change-this-password"])
    organization: str = Field(default="SecureGraph Demo Org", examples=["SecureGraph Labs"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["founder@example.com"])
    password: str = Field(..., examples=["change-this-password"])


def hash_password(password: str) -> str:
    """Hash a password using a portable stdlib PBKDF2 format."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), HASH_ITERATIONS)
    return f"pbkdf2_sha256${HASH_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against the stored hash."""
    try:
        algorithm, iterations, salt, expected = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations))
        return hmac.compare_digest(digest.hex(), expected)
    except Exception:
        return False


def _token(user: User, token_type: str, expires_delta: timedelta) -> str:
    payload = {
        "sub": user.id,
        "org_id": user.org_id,
        "role": user.role,
        "type": token_type,
        "exp": datetime.utcnow() + expires_delta,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def create_token_pair(user: User) -> dict:
    """Create access and refresh JWTs for a user."""
    return {
        "access_token": _token(user, "access", timedelta(minutes=settings.access_token_minutes)),
        "refresh_token": _token(user, "refresh", timedelta(days=settings.refresh_token_days)),
        "token_type": "bearer",
        "expires_in": settings.access_token_minutes * 60,
    }


def user_payload(user: User) -> dict:
    """Return user fields that are safe for the frontend."""
    return {"id": user.id, "email": user.email, "org_id": user.org_id, "role": user.role}


def decode_token(token: str) -> dict:
    """Decode and validate a JWT."""
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    """Resolve the current authenticated user from a Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    payload = decode_token(authorization.removeprefix("Bearer ").strip())
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Access token required")
    user = db.get(User, payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user


def optional_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User | None:
    """Return the current user when a token is present, otherwise allow demo access."""
    if not authorization:
        return None
    return current_user(authorization, db)


@router.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already exists")
    org = Organization(name=request.organization)
    db.add(org)
    db.flush()
    user = User(email=request.email, password_hash=hash_password(request.password), org_id=org.id)
    db.add(user)
    db.flush()
    db.add(Project(org_id=org.id, user_id=user.id, name="Default Project"))
    db.commit()
    db.refresh(user)
    return {**create_token_pair(user), "user": user_payload(user)}


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {**create_token_pair(user), "user": user_payload(user)}


@router.post("/refresh")
def refresh_token(authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing refresh token")
    payload = decode_token(authorization.removeprefix("Bearer ").strip())
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Refresh token required")
    user = db.get(User, payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return create_token_pair(user)


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"user": user_payload(user)}


@router.post("/logout")
def logout():
    return {"status": "ok"}
