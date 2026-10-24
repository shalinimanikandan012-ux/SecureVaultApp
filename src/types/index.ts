/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Domain Types
 */

export type SecurityEventType =
  | 'AUTH_LOGIN_SUCCESS'
  | 'AUTH_LOGIN_FAILURE'
  | 'AUTH_LOGOUT'
  | 'AUTH_REGISTER'
  | 'AUTH_ACCOUNT_LOCKED'
  | 'MFA_ENROLL_SUCCESS'
  | 'MFA_CHALLENGE_SUCCESS'
  | 'MFA_CHALLENGE_FAILURE'
  | 'MFA_RECOVERY_USED'
  | 'VAULT_MASTER_KEY_SET'
  | 'VAULT_UNLOCKED'
  | 'VAULT_UNLOCK_FAILED'
  | 'VAULT_LOCKED'
  | 'VAULT_AUTO_LOCKED'
  | 'NOTE_CREATED'
  | 'NOTE_UPDATED'
  | 'NOTE_DECRYPTED'
  | 'NOTE_DELETED'
  | 'FILE_UPLOADED_ENCRYPTED'
  | 'FILE_DOWNLOADED_DECRYPTED'
  | 'FILE_INTEGRITY_FAILED'
  | 'FILE_DELETED'
  | 'TAMPER_ATTEMPT_DETECTED'
  | 'AUDIT_LOG_EXPORT'
  | 'SECURITY_SETTINGS_CHANGED';

export type EventSeverity = 'INFO' | 'WARNING' | 'CRITICAL';

export interface User {
  id: string;
  email: string;
  username: string;
  passwordHash: string; // Argon2id / PBKDF2 representation
  passwordSalt: string;
  mfaEnabled: boolean;
  mfaSecret?: string; // base32 encoded
  recoveryCodeHashes: string[]; // SHA-256 hashes of single-use recovery codes
  createdAt: string;
  lastLoginAt: string | null;
  failedLoginAttempts: number;
  lockoutUntil: string | null;
}

export interface VaultMetadata {
  userId: string;
  salt: string; // Base64 salt used for Master Password derivation
  iterations: number; // e.g. 100,000 rounds PBKDF2-SHA256 (or Argon2id equivalent)
  algorithm: 'AES-256-GCM';
  // Canary payload: used to verify that master password is correct without ever storing master password
  canaryCiphertext: string;
  canaryNonce: string;
  canaryTag: string;
  updatedAt: string;
}

export interface EncryptedPayload {
  ciphertext: string; // Base64
  nonce: string; // Base64 (12 bytes / 96-bit IV)
  tag: string; // Base64 (16 bytes / 128-bit authentication tag)
  version: number;
}

export interface EncryptedNote {
  id: string;
  userId: string;
  title: string;
  category: string;
  tags: string[];
  encryptedPayload: EncryptedPayload;
  createdAt: string;
  updatedAt: string;
}

export interface DecryptedNote {
  id: string;
  userId: string;
  title: string;
  category: string;
  tags: string[];
  content: string; // Plaintext (only lives in React memory while unlocked)
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedFileRecord {
  id: string;
  userId: string;
  name: string;
  size: number;
  mimeType: string;
  sha256Checksum: string; // SHA-256 hash of original plaintext file
  encryptedPayload: EncryptedPayload;
  uploadedAt: string;
}

export interface SecurityEvent {
  id: string;
  userId: string;
  userEmail: string;
  type: SecurityEventType;
  severity: EventSeverity;
  message: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  metadata?: Record<string, unknown>;
}

export interface AuditLogEntry {
  id: string;
  index: number;
  timestamp: string;
  actorId: string;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId: string;
  status: 'SUCCESS' | 'FAILURE' | 'TAMPER_DETECTED';
  details: string;
  prevHash: string; // 64-char hex SHA-256 hash of previous block
  hash: string; // 64-char hex SHA-256 hash of this entry
}

export interface HashChainVerificationResult {
  isValid: boolean;
  totalChecked: number;
  brokenAtIndex: number | null;
  brokenEntryId?: string;
  expectedHash?: string;
  actualHash?: string;
  reason: string | null;
  verifiedAt: string;
}

export type ActiveTab =
  | 'dashboard'
  | 'notes'
  | 'files'
  | 'tamper-lab'
  | 'forensics'
  | 'settings'
  | 'college-demo'
  | 'code-docs';

export interface DemoStep {
  step: number;
  title: string;
  rubricArea: string;
  description: string;
  completed: boolean;
}
