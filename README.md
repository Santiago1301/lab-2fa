# Lab 2FA (TOTP) desde cero + Observabilidad con Prefect

| Carpeta | Contenido |
|---|---|
| `mobile-authenticator/` | App Authenticator en React Native (Expo). Calcula el TOTP (RFC 6238) sin conexión. |
| `backend-prefect/` | API FastAPI con Step-Up Auth, flujos de Prefect, base de datos SQLite y la web app de login (`web/`). |

## 1. Servidor de Prefect

```bash
cd backend-prefect
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/prefect server start
```

Dashboard: http://127.0.0.1:4200

## 2. Backend + web app de login

En otra terminal:

```bash
cd backend-prefect
PREFECT_API_URL=http://127.0.0.1:4200/api .venv/bin/uvicorn app.main:app --port 8000 --reload
```

- Web app: http://localhost:8000
- Documentación de la API: http://localhost:8000/docs
- Pruebas: `.venv/bin/python -m pytest -q`

Sin `PREFECT_API_URL` los flujos corren igual, pero en un servidor temporal que no se ve en el dashboard.

## 3. App móvil

```bash
cd mobile-authenticator
npm install
npx expo start --tunnel
```

Escanea el QR con la cámara del iPhone (requiere Expo Go con el SDK 58). `--tunnel` permite usarla aunque el celular esté en datos móviles o en otra red.

Prueba del algoritmo con los vectores del RFC 6238: `node src/lib/totp.test.ts`

## Endpoints

| Método | Ruta | Token | Qué hace |
|---|---|---|---|
| POST | `/auth/register` | — | Crea el usuario (contraseña con PBKDF2-SHA256). |
| POST | `/auth/login` | — | Flow `password-login`. Devuelve un `pre_auth_token` (scope `pre_auth`, 5 min). **No** da acceso a la bóveda. |
| POST | `/auth/2fa/setup` | `pre_auth` | Flow `provision-2fa`. Crea la config en `PENDING_VERIFICATION` y devuelve el QR `otpauth://` y 8 códigos de respaldo. Si ya está `ACTIVE` responde 409. |
| POST | `/auth/verify-2fa` | `pre_auth` | Flow `verify-2fa` (4 tasks). Devuelve el `access_token` con `mfa_verified: true`. |
| GET | `/api/boveda-secreta` | `access` | Recurso protegido. Exige `mfa_verified: true`. |

## Patrones implementados

- **Step-Up Auth** (`app/security.py`): los tokens llevan `scope`. El `pre_auth_token` solo sirve en `/auth/2fa/setup` y `/auth/verify-2fa`. El `access_token` solo sirve en las rutas protegidas.
- **Máquina de estados** (`app/state_machine.py`): `SIN_CONFIGURAR → PENDING_VERIFICATION → ACTIVE`. El paso a `ACTIVE` ocurre con el primer código TOTP válido. Mientras está pendiente se puede regenerar el QR.
- **Strategy** (`app/strategies.py`): `SecondFactorStrategy` con `TOTPStrategy` (ventanas C-1, C, C+1) y `BackupCodeStrategy` (códigos de un solo uso, guardados como hash).
- **Anti-Replay** (`app/replay_cache.py`): caché en memoria de `(user_id, código)` por 90 s. El marcado es atómico, así que dos peticiones simultáneas con el mismo código no pasan las dos.

## Flow `verify-2fa` en Prefect (`app/flows.py`)

1. `validate_pre_auth_state`: valida el `pre_auth_token` y lee el estado 2FA.
2. `check_anti_replay_cache`: si el código ya se usó, lanza `ReplayAttackDetected` y el flow queda **Failed** en esta task.
3. `execute_mfa_strategy`: ejecuta la estrategia y registra en qué ventana (C-1, C, C+1) hizo match.
4. `issue_elevated_session`: marca el código como usado, activa el 2FA si estaba pendiente y emite el JWT con `mfa_verified: true`.

La contraseña y el `pre_auth_token` se pasan como `SecretStr`, así que el dashboard los muestra como `**********`.

## Guion de la demo

1. **Paridad:** crea un usuario en la web, inicia sesión y escanea el QR con la app propia y con Google Authenticator. Los dos muestran el mismo código.
2. **Modo avión:** con la app ya abierta, activa el modo avión, espera a que cambie la ventana de 30 s e inicia sesión. Llegas a `/api/boveda-secreta`.
3. **Replay:** vuelve a iniciar sesión y usa el mismo código antes de que cambie. Responde 409 y en Prefect el flow `verify-2fa-totp` aparece en rojo en `check_anti_replay_cache`.
4. **Clock skew o respaldo:** en los logs de `execute_mfa_strategy` se ve la ventana que validó el código. También puedes marcar "Usar un código de respaldo" en la web.
