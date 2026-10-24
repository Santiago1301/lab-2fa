"""
Flujos de Prefect: cada endpoint de autenticación ejecuta un @flow y cada
paso es un @task observable en el dashboard (http://127.0.0.1:4200).

Los parámetros sensibles (contraseña, pre_auth_token) viajan como SecretStr
para que Prefect los muestre enmascarados en la UI.
"""
from prefect import flow, get_run_logger, task
from pydantic import SecretStr

from . import db, state_machine
from .replay_cache import ReplayAttackDetected, replay_cache
from .security import (
    SCOPE_PRE_AUTH,
    create_access_token,
    create_pre_auth_token,
    decode_token,
    generate_backup_codes,
    hash_backup_code,
    normalize_backup_code,
    verify_password,
)
from .state_machine import MfaStatus
from .strategies import get_strategy
from .totp import build_otpauth_uri, generate_secret


class InvalidCredentials(Exception):
    pass


class InvalidPreAuthState(Exception):
    pass


class InvalidSecondFactor(Exception):
    pass


# =============================================================================
# Flow principal: POST /auth/verify-2fa
# =============================================================================

@task(name="validate_pre_auth_state")
def validate_pre_auth_state(pre_auth_token: str) -> dict:
    logger = get_run_logger()
    try:
        claims = decode_token(pre_auth_token, SCOPE_PRE_AUTH)
    except Exception as e:
        logger.error(f"pre_auth_token rechazado: {e}")
        raise InvalidPreAuthState(str(e)) from e

    user = db.get_user(int(claims["sub"]))
    if user is None:
        raise InvalidPreAuthState("El usuario del token ya no existe")

    status = state_machine.current_status(user.id)
    if status is None:
        raise InvalidPreAuthState("El usuario no ha iniciado la activación de 2FA (/auth/2fa/setup)")

    logger.info(f"pre_auth_token válido para '{user.username}' (id={user.id}). Estado 2FA: {status.value}")
    return {"user_id": user.id, "username": user.username, "mfa_status": status.value}


@task(name="check_anti_replay_cache")
def check_anti_replay_cache(user_id: int, code: str) -> None:
    logger = get_run_logger()
    if replay_cache.was_used(user_id, code):
        elapsed = replay_cache.seconds_since_use(user_id, code) or 0
        logger.error(
            f"REPLAY ATTACK: el código {code} del usuario {user_id} ya se usó hace {elapsed:.0f}s "
            f"(se bloquea durante 90s)"
        )
        raise ReplayAttackDetected(f"El código {code} ya fue utilizado hace {elapsed:.0f} segundos")
    logger.info(f"El código {code} no ha sido usado en los últimos 90s")


@task(name="execute_mfa_strategy")
def execute_mfa_strategy(user_id: int, code: str, method: str, mfa_status: str) -> str | None:
    logger = get_run_logger()
    strategy = get_strategy(method)
    logger.info(f"Estrategia seleccionada: {type(strategy).__name__}")

    if method == "backup" and mfa_status != MfaStatus.ACTIVE.value:
        raise InvalidSecondFactor("Los códigos de respaldo solo sirven cuando el 2FA ya está ACTIVE")

    result = strategy.verify(db.get_mfa_config(user_id), code)
    if not result.valid:
        logger.error(f"Segundo factor rechazado: {result.detail}")
        raise InvalidSecondFactor(result.detail)

    if result.window:
        skew = {
            "C-1": "el reloj del celular está ATRASADO (~30s)",
            "C": "el reloj del celular está sincronizado",
            "C+1": "el reloj del celular está ADELANTADO (~30s)",
        }[result.window]
        logger.info(f"TOTP válido en la ventana {result.window}: {skew}. {result.detail}")
    else:
        logger.info(result.detail)
    return result.window


@task(name="issue_elevated_session")
def issue_elevated_session(user_id: int, username: str, code: str, method: str, mfa_status: str) -> dict:
    logger = get_run_logger()

    # Marcado atómico: si dos peticiones con el mismo código llegan a la vez, solo una gana
    if not replay_cache.mark_used(user_id, code):
        raise ReplayAttackDetected(f"El código {code} fue usado por otra petición concurrente")
    logger.info(f"Código {code} marcado como usado en la caché Anti-Replay (90s)")

    activated = False
    if mfa_status == MfaStatus.PENDING_VERIFICATION.value:
        state_machine.activate(user_id)
        activated = True
        logger.info(f"Máquina de estados: PENDING_VERIFICATION -> ACTIVE para '{username}'")

    token = create_access_token(user_id, username, method)
    logger.info(f"access_token emitido para '{username}' con mfa_verified=true")
    return {"access_token": token, "activated": activated}


@flow(name="verify-2fa", flow_run_name="verify-2fa-{method}")
def verify_2fa_flow(pre_auth_token: SecretStr, code: str, method: str = "totp") -> dict:
    code = code.strip()
    if method == "backup":
        code = normalize_backup_code(code)

    ctx = validate_pre_auth_state(pre_auth_token.get_secret_value())
    check_anti_replay_cache(ctx["user_id"], code)
    window = execute_mfa_strategy(ctx["user_id"], code, method, ctx["mfa_status"])
    session = issue_elevated_session(ctx["user_id"], ctx["username"], code, method, ctx["mfa_status"])
    return {**session, "window": window, "username": ctx["username"]}


# =============================================================================
# Flow de login: POST /auth/login (primer paso del Step-Up)
# =============================================================================

@task(name="validate_credentials")
def validate_credentials(username: str, password: str) -> dict:
    logger = get_run_logger()
    user = db.get_user_by_username(username)
    if user is None or not verify_password(password, user.password_hash):
        logger.warning(f"Credenciales inválidas para '{username}'")
        raise InvalidCredentials("Usuario o contraseña incorrectos")
    logger.info(f"Contraseña correcta para '{username}'")
    return {"user_id": user.id, "username": user.username}


@task(name="issue_pre_auth_token")
def issue_pre_auth_token(user_id: int, username: str) -> dict:
    logger = get_run_logger()
    status = state_machine.current_status(user_id)
    token = create_pre_auth_token(user_id, username)
    logger.info(
        f"pre_auth_token emitido (scope restringido a 2FA). Estado 2FA: "
        f"{status.value if status else 'SIN_CONFIGURAR'}"
    )
    return {"pre_auth_token": token, "mfa_status": status.value if status else None}


@flow(name="password-login", flow_run_name="login-{username}")
def password_login_flow(username: str, password: SecretStr) -> dict:
    user = validate_credentials(username, password.get_secret_value())
    return issue_pre_auth_token(user["user_id"], user["username"])


# =============================================================================
# Flow de aprovisionamiento: POST /auth/2fa/setup
# =============================================================================

@task(name="generate_totp_secret")
def generate_totp_secret(username: str) -> dict:
    secret = generate_secret()
    get_run_logger().info(f"Secreto TOTP de 160 bits generado para '{username}'")
    return {"secret": secret, "otpauth_uri": build_otpauth_uri(secret, username)}


@task(name="generate_backup_codes")
def generate_backup_codes_task() -> list[str]:
    codes = generate_backup_codes()
    get_run_logger().info(f"{len(codes)} códigos de respaldo generados (se guardan solo sus hashes)")
    return codes


@task(name="persist_pending_config")
def persist_pending_config(user_id: int, secret: str, backup_codes: list[str]) -> str:
    logger = get_run_logger()
    state_machine.start_provisioning(user_id, secret, [hash_backup_code(c) for c in backup_codes])
    logger.info("Máquina de estados: configuración 2FA guardada en PENDING_VERIFICATION")
    return MfaStatus.PENDING_VERIFICATION.value


@flow(name="provision-2fa", flow_run_name="provision-2fa")
def provision_2fa_flow(pre_auth_token: SecretStr) -> dict:
    ctx_claims = decode_token(pre_auth_token.get_secret_value(), SCOPE_PRE_AUTH)
    user_id, username = int(ctx_claims["sub"]), ctx_claims["username"]

    secret_info = generate_totp_secret(username)
    backup_codes = generate_backup_codes_task()
    status = persist_pending_config(user_id, secret_info["secret"], backup_codes)
    return {**secret_info, "backup_codes": backup_codes, "status": status}
