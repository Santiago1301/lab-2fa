"""
Pruebas de punta a punta del backend (pytest).
Correr desde backend-prefect/:  .venv/bin/python -m pytest -q
"""
import os
import tempfile

os.environ["LAB2FA_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.strategies import TOTPStrategy
from app.totp import base32_decode, get_counter, hotp, totp_for_counter

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def current_code(secret: str, offset: int = 0) -> str:
    return totp_for_counter(secret, get_counter() + offset)


def login(client, username="ana", password="secreta123") -> dict:
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return res.json()


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    "t, expected",
    [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (20000000000, "65353130")],
)
def test_rfc6238_vectors(t, expected):
    assert hotp(base32_decode(RFC_SECRET), t // 30, digits=8) == expected


def test_full_step_up_flow(client):
    assert client.post("/auth/register", json={"username": "ana", "password": "secreta123"}).status_code == 201
    assert client.post("/auth/login", json={"username": "ana", "password": "mala123"}).status_code == 401

    # Paso 1: login sin 2FA -> pre_auth_token y hay que configurar
    first = login(client)
    assert first["mfa_status"] is None
    pre = first["pre_auth_token"]

    # El pre_auth_token no abre la bóveda
    assert client.get("/api/boveda-secreta", headers=auth(pre)).status_code == 401

    # Aprovisionamiento -> PENDING_VERIFICATION
    setup = client.post("/auth/2fa/setup", headers=auth(pre)).json()
    assert setup["status"] == "PENDING_VERIFICATION"
    assert setup["otpauth_uri"].startswith("otpauth://totp/Lab2FA:ana?secret=")
    secret, backup_codes = setup["secret"], setup["backup_codes"]
    assert login(client)["mfa_status"] == "PENDING_VERIFICATION"

    # En PENDING no se aceptan códigos de respaldo
    res = client.post("/auth/verify-2fa", headers=auth(pre), json={"code": backup_codes[0], "method": "backup"})
    assert res.status_code == 401

    # Código incorrecto
    assert client.post("/auth/verify-2fa", headers=auth(pre), json={"code": "000000"}).status_code in (401, 409)

    # Primer código válido -> ACTIVE + access_token
    code = current_code(secret)
    res = client.post("/auth/verify-2fa", headers=auth(pre), json={"code": code})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["mfa_verified"] is True and body["mfa_activated_now"] is True
    access = body["access_token"]

    # Replay del mismo código -> rechazado
    res = client.post("/auth/verify-2fa", headers=auth(pre), json={"code": code})
    assert res.status_code == 409
    assert "Replay" in res.json()["detail"]

    # Ruta protegida con el access_token
    vault = client.get("/api/boveda-secreta", headers=auth(access))
    assert vault.status_code == 200 and vault.json()["mfa_verified"] is True

    # El access_token no sirve para verify-2fa (scopes separados)
    assert client.post("/auth/verify-2fa", headers=auth(access), json={"code": "123456"}).status_code == 401

    # Ya ACTIVE: no se puede regenerar el secreto con solo la contraseña
    pre2 = login(client)["pre_auth_token"]
    assert login(client)["mfa_status"] == "ACTIVE"
    assert client.post("/auth/2fa/setup", headers=auth(pre2)).status_code == 409

    # Código de respaldo: funciona una vez
    res = client.post("/auth/verify-2fa", headers=auth(pre2), json={"code": backup_codes[1].lower(), "method": "backup"})
    assert res.status_code == 200, res.text
    pre3 = login(client)["pre_auth_token"]
    res = client.post("/auth/verify-2fa", headers=auth(pre3), json={"code": backup_codes[1], "method": "backup"})
    assert res.status_code in (401, 409)


@pytest.mark.parametrize("offset, window", [(-1, "C-1"), (0, "C"), (1, "C+1")])
def test_totp_strategy_windows(offset, window):
    class Config:
        secret = RFC_SECRET

    now = 1_700_000_015  # mitad de una ventana
    strategy = TOTPStrategy(clock=lambda: now)
    code = totp_for_counter(RFC_SECRET, get_counter(now) + offset)
    result = strategy.verify(Config(), code)
    assert result.valid and result.window == window

    too_old = totp_for_counter(RFC_SECRET, get_counter(now) - 2)
    assert not strategy.verify(Config(), too_old).valid
