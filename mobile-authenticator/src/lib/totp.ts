/**
 * TOTP (RFC 6238) implementado desde cero.
 *
 * Solo usamos @noble/hashes para el HMAC-SHA1 (permitido por la guía).
 * El decodificador Base32, el contador, el empaquetado de 8 bytes
 * y el truncamiento dinámico están escritos a mano.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';

export const PERIOD = 30; // segundos por ventana
export const DIGITS = 6;

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Paso 1: Base32 (RFC 4648) -> bytes. Ignora espacios, guiones y relleno "=". */
export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  if (clean.length === 0) throw new Error('El secreto está vacío');

  const bytes: number[] = [];
  let buffer = 0; // acumulador de bits
  let bits = 0; // cuántos bits válidos hay en el acumulador

  for (const char of clean) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) throw new Error(`Carácter Base32 inválido: "${char}"`);
    buffer = (buffer << 5) | value; // cada carácter aporta 5 bits
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff); // sacamos un byte completo
    }
  }
  return new Uint8Array(bytes);
}

/** Paso 2: contador C = floor(UnixTime / 30). */
export function getCounter(unixSeconds: number = Date.now() / 1000): number {
  return Math.floor(unixSeconds / PERIOD);
}

/** Segundos que le quedan a la ventana actual (30..1). */
export function secondsRemaining(unixSeconds: number = Date.now() / 1000): number {
  return PERIOD - (Math.floor(unixSeconds) % PERIOD);
}

/** Paso 3: empaquetar C como entero de 8 bytes Big-Endian. */
export function counterToBytes(counter: number): Uint8Array {
  const out = new Uint8Array(8);
  const high = Math.floor(counter / 2 ** 32); // 32 bits altos
  const low = counter >>> 0; // 32 bits bajos
  for (let i = 0; i < 4; i++) {
    out[3 - i] = (high >>> (8 * i)) & 0xff;
    out[7 - i] = (low >>> (8 * i)) & 0xff;
  }
  return out;
}

/** Pasos 4 y 5: HMAC-SHA1 + truncamiento dinámico -> código de 6 dígitos. */
export function hotp(key: Uint8Array, counter: number, digits: number = DIGITS): string {
  const hash = hmac(sha1, key, counterToBytes(counter)); // 20 bytes

  const offset = hash[hash.length - 1] & 0x0f; // último byte (índice 19) & 0x0f
  const binary =
    ((hash[offset] & 0x7f) << 24) | // quitamos el bit de signo
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const code = binary % 10 ** digits;
  return code.toString().padStart(digits, '0');
}

/** Código TOTP para un secreto Base32 en un instante dado. */
export function totp(secretBase32: string, unixSeconds: number = Date.now() / 1000): string {
  return hotp(base32Decode(secretBase32), getCounter(unixSeconds));
}

/**
 * Extrae el secreto de una URI otpauth://totp/Label?secret=XXXX&issuer=YYY
 * Devuelve también el label e issuer para mostrarlos en la app.
 */
export function parseOtpauthUri(uri: string): { secret: string; label: string; issuer: string } {
  const match = uri.trim().match(/^otpauth:\/\/totp\/([^?]*)\?(.*)$/i);
  if (!match) throw new Error('No es una URI otpauth://totp/ válida');

  const label = decodeURIComponent(match[1] || '');
  const params: Record<string, string> = {};
  for (const pair of match[2].split('&')) {
    const [k, v = ''] = pair.split('=');
    params[decodeURIComponent(k).toLowerCase()] = decodeURIComponent(v);
  }
  if (!params.secret) throw new Error('La URI no tiene el parámetro "secret"');
  base32Decode(params.secret); // valida que sea Base32 correcto

  const issuer = params.issuer || (label.includes(':') ? label.split(':')[0] : '');
  return { secret: params.secret.toUpperCase(), label, issuer };
}
