"""
Process Manager / Máquina de Estados del aprovisionamiento 2FA.

    (sin config) --start--> PENDING_VERIFICATION --primer código válido--> ACTIVE

Mientras está en PENDING_VERIFICATION el usuario puede regenerar el QR
(por si nunca lo escaneó). Una vez ACTIVE, ya no se puede reemplazar el
secreto con solo la contraseña.
"""
from enum import Enum

from . import db


class MfaStatus(str, Enum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"


class InvalidTransition(Exception):
    pass


# estado actual (None = sin configurar) -> estados a los que puede pasar
TRANSITIONS: dict[MfaStatus | None, set[MfaStatus]] = {
    None: {MfaStatus.PENDING_VERIFICATION},
    MfaStatus.PENDING_VERIFICATION: {MfaStatus.PENDING_VERIFICATION, MfaStatus.ACTIVE},
    MfaStatus.ACTIVE: set(),
}


def current_status(user_id: int) -> MfaStatus | None:
    config = db.get_mfa_config(user_id)
    return MfaStatus(config.status) if config else None


def _ensure_allowed(user_id: int, target: MfaStatus) -> MfaStatus | None:
    current = current_status(user_id)
    if target not in TRANSITIONS[current]:
        name = current.value if current else "SIN_CONFIGURAR"
        raise InvalidTransition(f"No se puede pasar de {name} a {target.value}")
    return current


def start_provisioning(user_id: int, secret: str, backup_code_hashes: list[str]) -> None:
    _ensure_allowed(user_id, MfaStatus.PENDING_VERIFICATION)
    db.save_pending_config(user_id, secret, MfaStatus.PENDING_VERIFICATION.value, backup_code_hashes)


def activate(user_id: int) -> None:
    _ensure_allowed(user_id, MfaStatus.ACTIVE)
    db.update_status(user_id, MfaStatus.ACTIVE.value)
