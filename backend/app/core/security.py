"""
Core security primitives: password hashing and JWT access tokens.

Design notes:
- Passwords are hashed with bcrypt (via passlib) — never stored or logged in plaintext.
- Access tokens are short-lived signed JWTs (HS256) carrying only non-sensitive claims
  (user id, org id, role code, expiry). They are NOT a session store — revocation is
  handled by short expiry + (optionally) a server-side denylist for logout/compromise.
- SECRET_KEY strength is enforced at startup in app.core.config.Settings.validate_production_safety.
"""
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import jwt
from passlib.context import CryptContext

from app.core.config import settings

logger = logging.getLogger("mailintel.security")

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=settings.BCRYPT_ROUNDS)

TOKEN_TYPE_ACCESS = "access"


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password for storage. Never store plaintext passwords."""
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Constant-time verification of a plaintext password against its stored hash."""
    if not password_hash:
        return False
    try:
        return _pwd_context.verify(plain_password, password_hash)
    except Exception:
        # Malformed hash, etc. — never raise; just treat as invalid credentials.
        return False


def is_password_strong_enough(password: str) -> Optional[str]:
    """
    Minimal, MVP-appropriate password policy. Returns an error message if the
    password is too weak, or None if acceptable.
    """
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if password.lower() in ("password", "password123", "changeme", "letmein", "qwerty123"):
        return "Password is too common. Please choose a stronger password."
    categories = 0
    if any(c.islower() for c in password):
        categories += 1
    if any(c.isupper() for c in password):
        categories += 1
    if any(c.isdigit() for c in password):
        categories += 1
    if any(not c.isalnum() for c in password):
        categories += 1
    if categories < 3:
        return "Password must contain at least 3 of: lowercase, uppercase, digit, symbol."
    return None


def create_access_token(
    *,
    user_id: uuid.UUID,
    organization_id: Optional[uuid.UUID],
    role_code: str,
    expires_minutes: Optional[int] = None,
) -> str:
    """Create a signed, short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire_delta = timedelta(minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "org": str(organization_id) if organization_id else None,
        "role": role_code,
        "type": TOKEN_TYPE_ACCESS,
        "iat": int(now.timestamp()),
        "exp": now + expire_delta,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify a JWT access token. Raises jwt.PyJWTError subclasses on any
    failure (expired, bad signature, malformed, wrong type) — callers must catch these
    and respond with 401, never leaking which specific check failed.
    """
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    if payload.get("type") != TOKEN_TYPE_ACCESS:
        raise jwt.InvalidTokenError("Not an access token")
    return payload
