"""
TOTP (RFC 6238) del lado del servidor.

Es el mismo algoritmo que corre la app móvil: el backend y el celular
nunca se comunican, solo comparten el secreto y el reloj.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

PERIOD = 30
DIGITS = 6
ISSUER = "Lab2FA"


def generate_secret(num_bytes: int = 20) -> str:
    """Secreto aleatorio de 160 bits en Base32 (sin relleno '=')."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode().rstrip("=")


def base32_decode(secret: str) -> bytes:
    clean = secret.upper().replace(" ", "").replace("-", "").rstrip("=")
    padding = "=" * (-len(clean) % 8)
    return base64.b32decode(clean + padding)


def get_counter(unix_seconds: float | None = None) -> int:
    """C = floor(UnixTime / 30)"""
    if unix_seconds is None:
        unix_seconds = time.time()
    return int(unix_seconds // PERIOD)


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    # Contador como entero de 8 bytes Big-Endian
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()

    # Truncamiento dinámico
    offset = digest[19] & 0x0F
    binary = (
        (digest[offset] & 0x7F) << 24
        | digest[offset + 1] << 16
        | digest[offset + 2] << 8
        | digest[offset + 3]
    )
    return str(binary % 10**digits).zfill(digits)


def totp_for_counter(secret: str, counter: int) -> str:
    return hotp(base32_decode(secret), counter)


def build_otpauth_uri(secret: str, username: str, issuer: str = ISSUER) -> str:
    label = f"{quote(issuer)}:{quote(username)}"
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )
