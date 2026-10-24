"""Hash de contraseñas y emisión de tokens (pre-auth y access)."""
import hashlib
import hmac
import os
import secrets
import time

import jwt

JWT_SECRET = os.getenv("LAB2FA_JWT_SECRET", "cambia-este-secreto-en-produccion-lab2fa")
JWT_ALGORITHM = "HS256"

PRE_AUTH_TTL = 5 * 60  # el pre_auth_token vive 5 minutos
ACCESS_TTL = 15 * 60

SCOPE_PRE_AUTH = "pre_auth"  # solo sirve para /auth/2fa/setup y /auth/verify-2fa
SCOPE_ACCESS = "access"

_PBKDF2_ITERATIONS = 200_000


class InvalidToken(Exception):
    pass


# --- Contraseñas --------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(digest.hex(), digest_hex)


# --- Códigos de respaldo ------------------------------------------------------

_BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sin 0/O ni 1/I para evitar confusiones


def generate_backup_codes(count: int = 8) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_backup_code(code: str) -> str:
    return code.upper().replace("-", "").replace(" ", "")


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(normalize_backup_code(code).encode()).hexdigest()


# --- Tokens -------------------------------------------------------------------

def _encode(claims: dict, ttl: int) -> str:
    now = int(time.time())
    return jwt.encode({**claims, "iat": now, "exp": now + ttl}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_pre_auth_token(user_id: int, username: str) -> str:
    return _encode(
        {"sub": str(user_id), "username": username, "scope": SCOPE_PRE_AUTH, "mfa_verified": False},
        PRE_AUTH_TTL,
    )


def create_access_token(user_id: int, username: str, method: str) -> str:
    return _encode(
        {
            "sub": str(user_id),
            "username": username,
            "scope": SCOPE_ACCESS,
            "mfa_verified": True,
            "amr": ["pwd", "otp" if method == "totp" else "backup_code"],
        },
        ACCESS_TTL,
    )


def decode_token(token: str, expected_scope: str) -> dict:
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as e:
        raise InvalidToken("El token expiró") from e
    except jwt.InvalidTokenError as e:
        raise InvalidToken("Token inválido") from e
    if claims.get("scope") != expected_scope:
        raise InvalidToken(f"Este token no sirve para esta operación (scope '{claims.get('scope')}')")
    return claims
