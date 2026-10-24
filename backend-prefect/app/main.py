"""API de autenticación escalonada (Step-Up Auth) con FastAPI."""
import base64
import io
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import qrcode
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from . import db
from .flows import (
    InvalidCredentials,
    InvalidPreAuthState,
    InvalidSecondFactor,
    password_login_flow,
    provision_2fa_flow,
    verify_2fa_flow,
)
from .replay_cache import ReplayAttackDetected
from .security import SCOPE_ACCESS, InvalidToken, decode_token, hash_password
from .state_machine import InvalidTransition

@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="Lab 2FA - Step-Up Auth", lifespan=lifespan)
bearer = HTTPBearer(auto_error=False)
WEB_DIR = Path(__file__).resolve().parent.parent / "web"


# --- Modelos ------------------------------------------------------------------

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)


class VerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)
    method: Literal["totp", "backup"] = "totp"


def _bearer_token(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Falta el header Authorization: Bearer <token>")
    return creds.credentials


def _qr_data_uri(text: str) -> str:
    buf = io.BytesIO()
    qrcode.make(text, box_size=8, border=2).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# --- Endpoints de autenticación -----------------------------------------------

@app.post("/auth/register", status_code=201)
def register(body: Credentials):
    username = body.username.strip().lower()
    if db.get_user_by_username(username):
        raise HTTPException(status.HTTP_409_CONFLICT, "Ese usuario ya existe")
    user = db.create_user(username, hash_password(body.password))
    return {"id": user.id, "username": user.username}


@app.post("/auth/login")
def login(body: Credentials):
    """Paso 1 del Step-Up: NO da acceso, solo un pre_auth_token para el segundo factor."""
    try:
        result = password_login_flow(body.username.strip().lower(), SecretStr(body.password))
    except InvalidCredentials as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
    return {
        "pre_auth_token": result["pre_auth_token"],
        "token_type": "bearer",
        "mfa_status": result["mfa_status"],
        "next_step": "/auth/verify-2fa" if result["mfa_status"] == "ACTIVE" else "/auth/2fa/setup",
    }


@app.post("/auth/2fa/setup")
def setup_2fa(token: str = Depends(_bearer_token)):
    """Inicia el aprovisionamiento: crea la config en PENDING_VERIFICATION y devuelve el QR."""
    try:
        result = provision_2fa_flow(SecretStr(token))
    except InvalidToken as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
    except InvalidTransition:
        raise HTTPException(status.HTTP_409_CONFLICT, "El 2FA ya está ACTIVE para este usuario")
    return {
        "status": result["status"],
        "secret": result["secret"],
        "otpauth_uri": result["otpauth_uri"],
        "qr_png": _qr_data_uri(result["otpauth_uri"]),
        "backup_codes": result["backup_codes"],
    }


@app.post("/auth/verify-2fa")
def verify_2fa(body: VerifyRequest, token: str = Depends(_bearer_token)):
    """Paso 2 del Step-Up: ejecuta el flow de Prefect y entrega el access_token definitivo."""
    try:
        result = verify_2fa_flow(SecretStr(token), body.code, body.method)
    except InvalidPreAuthState as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
    except ReplayAttackDetected as e:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Replay attack detectado: {e}")
    except InvalidSecondFactor as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
    return {
        "access_token": result["access_token"],
        "token_type": "bearer",
        "mfa_verified": True,
        "mfa_activated_now": result["activated"],
        "window": result["window"],
    }


# --- Recurso protegido --------------------------------------------------------

def require_mfa_session(token: str = Depends(_bearer_token)) -> dict:
    try:
        claims = decode_token(token, SCOPE_ACCESS)
    except InvalidToken as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
    if claims.get("mfa_verified") is not True:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Se requiere una sesión con mfa_verified=true")
    return claims


@app.get("/api/boveda-secreta")
def boveda_secreta(claims: dict = Depends(require_mfa_session)):
    return {
        "mensaje": f"Bienvenido a la bóveda, {claims['username']}. Pasaste los dos factores.",
        "secreto": "La respuesta es 42",
        "mfa_verified": claims["mfa_verified"],
        "metodos": claims.get("amr", []),
    }


# La web app de login se sirve desde la misma API (sin problemas de CORS)
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
