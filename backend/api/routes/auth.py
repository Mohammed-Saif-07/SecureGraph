from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from core.config import settings
from core.sql_db import Organization, User, get_db

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    organization: str = "SecureGraph Demo Org"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def _token(user: User) -> str:
    payload = {"sub": user.id, "org_id": user.org_id, "role": user.role, "exp": datetime.utcnow() + timedelta(hours=8)}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


@router.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already exists")
    org = Organization(name=request.organization)
    db.add(org)
    db.flush()
    user = User(email=request.email, password_hash=pwd_context.hash(request.password), org_id=org.id)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"access_token": _token(user), "token_type": "bearer", "user": {"id": user.id, "email": user.email, "org_id": user.org_id}}


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not pwd_context.verify(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": _token(user), "token_type": "bearer", "user": {"id": user.id, "email": user.email, "org_id": user.org_id}}
