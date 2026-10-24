/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Cryptographic Service
 * Real AES-256-GCM, PBKDF2 Key Derivation, SHA-256 Hash Chaining, & RFC 6238 TOTP
 */

import { EncryptedPayload } from '../types';

export const CANARY_PLAINTEXT = 'SECUREVAULT_VERIFY_OK_v1';
export const PBKDF2_ITERATIONS = 100000; // OWASP recommendation for PBKDF2-SHA256
export const NONCE_LENGTH_BYTES = 12; // 96 bits recommended for AES-GCM
export const TAG_LENGTH_BITS = 128; // 16 bytes authentication tag

// --- Buffer & Encoding Helpers ---

export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

export function generateRandomBytes(length: number): Uint8Array {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return array;
}

// --- SHA-256 Hashing ---

export async function sha256Hex(data: string | ArrayBuffer): Promise<string> {
  const buffer =
    typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}

// --- Key Derivation (PBKDF2-SHA256) ---

export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  iterations = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const passwordBuffer = new TextEncoder().encode(password);

  // Import raw password as key material
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive AES-GCM 256-bit key
  const derivedKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // Never allow key extraction
    ['encrypt', 'decrypt']
  );

  return derivedKey;
}

// --- Real AES-256-GCM Encryption / Decryption ---

/**
 * Encrypts plaintext using AES-256-GCM.
 * Generates a fresh cryptographically random 96-bit nonce for every single call.
 * Separates ciphertext and 128-bit authentication tag for explicit AEAD verification.
 */
export async function encryptAESGCM(
  plaintext: string | ArrayBuffer,
  key: CryptoKey,
  additionalData?: string
): Promise<EncryptedPayload> {
  const plaintextBuffer =
    typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;

  // Fresh 96-bit (12-byte) nonce
  const nonce = generateRandomBytes(NONCE_LENGTH_BYTES);

  const algorithm: AesGcmParams = {
    name: 'AES-GCM',
    iv: nonce as BufferSource,
    tagLength: TAG_LENGTH_BITS,
  };

  if (additionalData) {
    algorithm.additionalData = new TextEncoder().encode(additionalData);
  }

  // WebCrypto AES-GCM outputs [ciphertext bytes ... 16 tag bytes]
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    algorithm,
    key,
    plaintextBuffer
  );

  const totalLength = encryptedBuffer.byteLength;
  const tagByteLength = TAG_LENGTH_BITS / 8; // 16 bytes
  const ciphertextLength = totalLength - tagByteLength;

  const ciphertextArray = new Uint8Array(encryptedBuffer, 0, ciphertextLength);
  const tagArray = new Uint8Array(encryptedBuffer, ciphertextLength, tagByteLength);

  return {
    ciphertext: arrayBufferToBase64(ciphertextArray),
    nonce: arrayBufferToBase64(nonce),
    tag: arrayBufferToBase64(tagArray),
    version: 1,
  };
}

/**
 * Decrypts AES-256-GCM payload.
 * Reconstitutes ciphertext and tag, verifies authentication tag against nonce and ciphertext.
 * Throws an error if ciphertext or tag was modified (tamper detection).
 */
export async function decryptAESGCM(
  payload: EncryptedPayload,
  key: CryptoKey,
  additionalData?: string
): Promise<ArrayBuffer> {
  const ciphertextBuffer = base64ToArrayBuffer(payload.ciphertext);
  const nonceBuffer = base64ToArrayBuffer(payload.nonce);
  const tagBuffer = base64ToArrayBuffer(payload.tag);

  // Combine ciphertext and tag for WebCrypto decrypt
  const combined = new Uint8Array(ciphertextBuffer.byteLength + tagBuffer.byteLength);
  combined.set(new Uint8Array(ciphertextBuffer), 0);
  combined.set(new Uint8Array(tagBuffer), ciphertextBuffer.byteLength);

  const algorithm: AesGcmParams = {
    name: 'AES-GCM',
    iv: nonceBuffer as BufferSource,
    tagLength: TAG_LENGTH_BITS,
  };

  if (additionalData) {
    algorithm.additionalData = new TextEncoder().encode(additionalData);
  }

  // Will throw DOMException "OperationError" if tag fails verification or ciphertext tampered
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    algorithm,
    key,
    combined
  );

  return decryptedBuffer;
}

export async function decryptAESGCMToString(
  payload: EncryptedPayload,
  key: CryptoKey,
  additionalData?: string
): Promise<string> {
  const buffer = await decryptAESGCM(payload, key, additionalData);
  return new TextDecoder().decode(buffer);
}

// --- Master Password Verification (Canary) ---

export async function createVaultCanary(
  masterKey: CryptoKey
): Promise<{ canaryCiphertext: string; canaryNonce: string; canaryTag: string }> {
  const payload = await encryptAESGCM(CANARY_PLAINTEXT, masterKey);
  return {
    canaryCiphertext: payload.ciphertext,
    canaryNonce: payload.nonce,
    canaryTag: payload.tag,
  };
}

export async function verifyMasterPasswordKey(
  candidateKey: CryptoKey,
  canaryPayload: { canaryCiphertext: string; canaryNonce: string; canaryTag: string }
): Promise<boolean> {
  try {
    const decrypted = await decryptAESGCMToString(
      {
        ciphertext: canaryPayload.canaryCiphertext,
        nonce: canaryPayload.canaryNonce,
        tag: canaryPayload.canaryTag,
        version: 1,
      },
      candidateKey
    );
    return decrypted === CANARY_PLAINTEXT;
  } catch {
    return false;
  }
}

// --- TOTP Implementation (RFC 6238 / RFC 4226) ---

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateRandomBase32Secret(length = 16): string {
  const bytes = generateRandomBytes(length);
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += BASE32_ALPHABET[bytes[i] % 32];
  }
  return secret;
}

export function base32ToBytes(base32: string): Uint8Array {
  const cleaned = base32.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = '';
  for (let i = 0; i < cleaned.length; i++) {
    const val = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.substring(i * 8, (i + 1) * 8), 2);
  }
  return bytes;
}

export async function computeTOTP(
  secretBase32: string,
  timeOffsetSteps = 0,
  stepSeconds = 30
): Promise<{ code: string; secondsRemaining: number }> {
  const now = Math.floor(Date.now() / 1000);
  const timeStep = Math.floor(now / stepSeconds) + timeOffsetSteps;
  const secondsRemaining = stepSeconds - (now % stepSeconds);

  // Time step counter as 8-byte big-endian
  const counterBuffer = new ArrayBuffer(8);
  const view = new DataView(counterBuffer);
  view.setBigUint64(0, BigInt(timeStep), false);

  const secretBytes = base32ToBytes(secretBase32);

  // HMAC-SHA1
  const hmacKey = await window.crypto.subtle.importKey(
    'raw',
    secretBytes as BufferSource,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await window.crypto.subtle.sign('HMAC', hmacKey, counterBuffer);
  const sigBytes = new Uint8Array(signature);

  // Dynamic truncation (RFC 4226 Section 5.4)
  const offset = sigBytes[sigBytes.length - 1] & 0x0f;
  const binary =
    ((sigBytes[offset] & 0x7f) << 24) |
    ((sigBytes[offset + 1] & 0xff) << 16) |
    ((sigBytes[offset + 2] & 0xff) << 8) |
    (sigBytes[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return {
    code: otp.toString().padStart(6, '0'),
    secondsRemaining,
  };
}

export async function verifyTOTP(
  token: string,
  secretBase32: string,
  windowTolerance = 1 // Check ±1 step (30s drift window)
): Promise<boolean> {
  const cleanToken = token.trim();
  if (cleanToken.length !== 6 || !/^\d+$/.test(cleanToken)) {
    return false;
  }

  for (let step = -windowTolerance; step <= windowTolerance; step++) {
    const { code } = await computeTOTP(secretBase32, step);
    if (code === cleanToken) {
      return true;
    }
  }
  return false;
}

// Generate single-use recovery codes
export async function generateRecoveryCodes(
  count = 8
): Promise<{ plaintextCodes: string[]; hashedCodes: string[] }> {
  const plaintextCodes: string[] = [];
  const hashedCodes: string[] = [];

  for (let i = 0; i < count; i++) {
    const raw = generateRandomBytes(5);
    const code = Array.from(raw)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join('')
      .slice(0, 10);
    const formatted = `${code.slice(0, 5)}-${code.slice(5, 10)}`;
    const hash = await sha256Hex(formatted);
    plaintextCodes.push(formatted);
    hashedCodes.push(hash);
  }

  return { plaintextCodes, hashedCodes };
}

// --- Tamper Simulation Utilities for Educational Lab ---

export function flipBitInBase64(base64: string, byteIndex = 0): string {
  const buffer = base64ToArrayBuffer(base64);
  const bytes = new Uint8Array(buffer);
  if (bytes.length > 0) {
    const idx = Math.min(byteIndex, bytes.length - 1);
    bytes[idx] ^= 0x01; // flip lowest bit
  }
  return arrayBufferToBase64(bytes);
}
