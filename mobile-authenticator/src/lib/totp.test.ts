/**
 * Pruebas con los vectores oficiales del RFC 6238 (Apéndice B, SHA1).
 * Correr con:  node lib/totp.test.ts
 */
import { base32Decode, hotp, getCounter, parseOtpauthUri, totp } from './totp.ts';

// "12345678901234567890" en ASCII, codificado en Base32
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// [tiempo Unix, código de 8 dígitos del RFC]
const vectors: [number, string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'], // año 2603: verifica que el contador de 64 bits funcione
];

let failed = 0;
const check = (name: string, got: string, expected: string) => {
  const ok = got === expected;
  if (!ok) failed++;
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${name}: obtenido ${got}, esperado ${expected}`);
};

const key = base32Decode(RFC_SECRET);
check('Base32 decode', new TextDecoder().decode(key), '12345678901234567890');

for (const [t, expected8] of vectors) {
  const c = getCounter(t);
  check(`T=${t} (8 díg)`, hotp(key, c, 8), expected8);
  check(`T=${t} (6 díg)`, totp(RFC_SECRET, t), expected8.slice(-6));
}

const parsed = parseOtpauthUri(
  'otpauth://totp/Lab2FA:santiago%40correo.com?secret=JBSWY3DPEHPK3PXP&issuer=Lab2FA'
);
check('URI secret', parsed.secret, 'JBSWY3DPEHPK3PXP');
check('URI issuer', parsed.issuer, 'Lab2FA');

console.log(failed === 0 ? '\nTodas las pruebas pasaron ✅' : `\n${failed} pruebas fallaron ❌`);
process.exit(failed === 0 ? 0 : 1);
