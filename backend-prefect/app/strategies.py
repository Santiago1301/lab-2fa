"""Strategy Pattern para el segundo factor."""
import hmac
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from . import db
from .security import hash_backup_code, normalize_backup_code
from .totp import get_counter, totp_for_counter


@dataclass
class StrategyResult:
    valid: bool
    detail: str
    window: str | None = None  # solo TOTP: "C-1", "C" o "C+1"


class SecondFactorStrategy(ABC):
    name: str

    @abstractmethod
    def verify(self, config: db.MfaConfig, code: str) -> StrategyResult: ...


class TOTPStrategy(SecondFactorStrategy):
    name = "totp"
    # Se prueba primero la ventana actual y luego las vecinas
    WINDOWS = ((0, "C"), (-1, "C-1"), (1, "C+1"))

    def __init__(self, clock=time.time):
        self._clock = clock

    def verify(self, config: db.MfaConfig, code: str) -> StrategyResult:
        code = code.strip()
        if len(code) != 6 or not code.isdigit():
            return StrategyResult(False, "El código TOTP debe tener 6 dígitos")

        counter = get_counter(self._clock())
        for offset, label in self.WINDOWS:
            expected = totp_for_counter(config.secret, counter + offset)
            if hmac.compare_digest(expected, code):
                return StrategyResult(True, f"Match en la ventana {label} (contador {counter + offset})", label)
        return StrategyResult(False, "El código no coincide con ninguna ventana (C-1, C, C+1)")


class BackupCodeStrategy(SecondFactorStrategy):
    name = "backup"

    def verify(self, config: db.MfaConfig, code: str) -> StrategyResult:
        if len(normalize_backup_code(code)) != 8:
            return StrategyResult(False, "El código de respaldo tiene el formato XXXX-XXXX")
        if not db.consume_backup_code(config.user_id, hash_backup_code(code)):
            return StrategyResult(False, "Código de respaldo inválido o ya usado")
        remaining = len(db.get_mfa_config(config.user_id).backup_code_hashes)
        return StrategyResult(True, f"Código de respaldo consumido. Quedan {remaining}")


STRATEGIES: dict[str, SecondFactorStrategy] = {
    TOTPStrategy.name: TOTPStrategy(),
    BackupCodeStrategy.name: BackupCodeStrategy(),
}


def get_strategy(method: str) -> SecondFactorStrategy:
    try:
        return STRATEGIES[method]
    except KeyError:
        raise ValueError(f"Método de segundo factor desconocido: {method}") from None
