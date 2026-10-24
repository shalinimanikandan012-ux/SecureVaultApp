/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Vault Management Context
 * Secure In-Memory Master Key Storage, Auto-Lock, & Encrypted Data Operations
 */

import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { recordAuditEvent } from '../services/auditService';
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  createVaultCanary,
  decryptAESGCMToString,
  deriveKeyFromPassword,
  encryptAESGCM,
  generateRandomBytes,
  PBKDF2_ITERATIONS,
  verifyMasterPasswordKey,
} from '../services/crypto';
import {
  deleteEncryptedNote,
  getEncryptedNotes,
  getVaultMetadata,
  logSecurityEvent,
  saveEncryptedNote,
  saveVaultMetadata,
} from '../services/storage';
import { DecryptedNote, EncryptedNote, VaultMetadata } from '../types';
import { useAuth } from './AuthContext';

interface VaultContextType {
  isVaultConfigured: boolean;
  isVaultUnlocked: boolean;
  autoLockMinutes: number;
  secondsUntilAutoLock: number;
  decryptedNotes: DecryptedNote[];
  rawEncryptedNotes: EncryptedNote[];
  isLoadingNotes: boolean;
  setupMasterPassword: (password: string) => Promise<{ success: boolean; error?: string }>;
  unlockVault: (password: string) => Promise<{ success: boolean; error?: string }>;
  lockVault: (reason?: string) => void;
  setAutoLockDuration: (minutes: number) => void;
  createNote: (
    title: string,
    content: string,
    category: string,
    tags: string[]
  ) => Promise<{ success: boolean; note?: DecryptedNote; error?: string }>;
  editNote: (
    id: string,
    title: string,
    content: string,
    category: string,
    tags: string[]
  ) => Promise<{ success: boolean; error?: string }>;
  removeNote: (id: string) => Promise<{ success: boolean; error?: string }>;
  getMasterKeyForOperations: () => CryptoKey | null;
  refreshVaultState: () => void;
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

export const VaultProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { currentUser } = useAuth();
  const [masterKey, setMasterKey] = useState<CryptoKey | null>(null);
  const [isVaultConfigured, setIsVaultConfigured] = useState(false);
  const [autoLockMinutes, setAutoLockMinutes] = useState(10);
  const [secondsUntilAutoLock, setSecondsUntilAutoLock] = useState(600);
  const [decryptedNotes, setDecryptedNotes] = useState<DecryptedNote[]>([]);
  const [rawEncryptedNotes, setRawEncryptedNotes] = useState<EncryptedNote[]>([]);
  const [isLoadingNotes, setIsLoadingNotes] = useState(false);

  const lastActivityRef = useRef(Date.now());
  const timerRef = useRef<number | null>(null);

  // Check if vault is configured whenever current user changes
  useEffect(() => {
    if (!currentUser) {
      setMasterKey(null);
      setIsVaultConfigured(false);
      setDecryptedNotes([]);
      setRawEncryptedNotes([]);
      return;
    }

    const meta = getVaultMetadata(currentUser.id);
    setIsVaultConfigured(!!meta);
    setMasterKey(null);
    setDecryptedNotes([]);
    setRawEncryptedNotes(getEncryptedNotes(currentUser.id));
  }, [currentUser]);

  // Inactivity auto-lock countdown timer
  useEffect(() => {
    if (!masterKey || !currentUser) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    lastActivityRef.current = Date.now();
    setSecondsUntilAutoLock(autoLockMinutes * 60);

    const handleUserActivity = () => {
      lastActivityRef.current = Date.now();
    };

    window.addEventListener('mousemove', handleUserActivity);
    window.addEventListener('keydown', handleUserActivity);
    window.addEventListener('click', handleUserActivity);

    timerRef.current = window.setInterval(() => {
      const elapsedSeconds = Math.floor(
        (Date.now() - lastActivityRef.current) / 1000
      );
      const remaining = Math.max(0, autoLockMinutes * 60 - elapsedSeconds);
      setSecondsUntilAutoLock(remaining);

      if (remaining <= 0) {
        lockVault('Auto-locked due to user inactivity');
      }
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      window.removeEventListener('mousemove', handleUserActivity);
      window.removeEventListener('keydown', handleUserActivity);
      window.removeEventListener('click', handleUserActivity);
    };
  }, [masterKey, autoLockMinutes, currentUser]);

  const lockVault = (reason = 'Manual user lock') => {
    setMasterKey(null);
    setDecryptedNotes([]); // Purge all decrypted sensitive data from memory immediately

    if (currentUser) {
      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'VAULT_LOCKED',
        severity: 'INFO',
        message: `Vault locked (${reason}) for ${currentUser.email}`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'VAULT_LOCK',
        resourceType: 'VAULT',
        resourceId: currentUser.id,
        status: 'SUCCESS',
        details: `Cryptographic keys purged from memory: ${reason}`,
      });
    }
  };

  const setupMasterPassword = async (
    password: string
  ): Promise<{ success: boolean; error?: string }> => {
    if (!currentUser) return { success: false, error: 'User not authenticated' };
    if (password.length < 12) {
      return {
        success: false,
        error: 'Master password must be at least 12 characters long.',
      };
    }

    try {
      const saltBytes = generateRandomBytes(16);
      const saltBase64 = arrayBufferToBase64(saltBytes);

      // Derive 256-bit AES-GCM Key
      const key = await deriveKeyFromPassword(
        password,
        saltBytes,
        PBKDF2_ITERATIONS
      );

      // Create canary encryption
      const canary = await createVaultCanary(key);

      const metadata: VaultMetadata = {
        userId: currentUser.id,
        salt: saltBase64,
        iterations: PBKDF2_ITERATIONS,
        algorithm: 'AES-256-GCM',
        canaryCiphertext: canary.canaryCiphertext,
        canaryNonce: canary.canaryNonce,
        canaryTag: canary.canaryTag,
        updatedAt: new Date().toISOString(),
      };

      saveVaultMetadata(metadata);
      setMasterKey(key);
      setIsVaultConfigured(true);

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'VAULT_MASTER_KEY_SET',
        severity: 'INFO',
        message: `Vault initialized with 256-bit AES-GCM key derived via PBKDF2 (${PBKDF2_ITERATIONS} iterations)`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'VAULT_INITIALIZE',
        resourceType: 'VAULT',
        resourceId: currentUser.id,
        status: 'SUCCESS',
        details: `Master key derived and verification canary anchored for ${currentUser.email}`,
      });

      return { success: true };
    } catch (err) {
      console.error('Failed to setup master key:', err);
      return { success: false, error: 'Cryptographic derivation failed.' };
    }
  };

  const unlockVault = async (
    password: string
  ): Promise<{ success: boolean; error?: string }> => {
    if (!currentUser) return { success: false, error: 'User not authenticated' };

    const metadata = getVaultMetadata(currentUser.id);
    if (!metadata) {
      return { success: false, error: 'Vault has not been initialized yet.' };
    }

    try {
      const saltBytes = new Uint8Array(base64ToArrayBuffer(metadata.salt));
      const candidateKey = await deriveKeyFromPassword(
        password,
        saltBytes,
        metadata.iterations
      );

      const isKeyValid = await verifyMasterPasswordKey(candidateKey, {
        canaryCiphertext: metadata.canaryCiphertext,
        canaryNonce: metadata.canaryNonce,
        canaryTag: metadata.canaryTag,
      });

      if (!isKeyValid) {
        logSecurityEvent({
          userId: currentUser.id,
          userEmail: currentUser.email,
          type: 'VAULT_UNLOCK_FAILED',
          severity: 'WARNING',
          message: `Failed vault unlock attempt: GCM tag validation failure for canary`,
          timestamp: new Date().toISOString(),
          ipAddress: '127.0.0.1',
          userAgent: navigator.userAgent,
        });

        await recordAuditEvent({
          actorId: currentUser.id,
          actorEmail: currentUser.email,
          action: 'VAULT_UNLOCK',
          resourceType: 'VAULT',
          resourceId: currentUser.id,
          status: 'FAILURE',
          details: `Authentication tag check rejected candidate master key for ${currentUser.email}`,
        });

        return {
          success: false,
          error: 'Incorrect master password. GCM integrity check failed.',
        };
      }

      // Vault is unlocked!
      setMasterKey(candidateKey);
      lastActivityRef.current = Date.now();

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'VAULT_UNLOCKED',
        severity: 'INFO',
        message: `Vault successfully unlocked with verified AES-256-GCM master key`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'VAULT_UNLOCK',
        resourceType: 'VAULT',
        resourceId: currentUser.id,
        status: 'SUCCESS',
        details: `Vault unlocked with valid canary verification`,
      });

      // Decrypt all existing notes into memory
      decryptNotesInMemory(candidateKey, currentUser.id);

      return { success: true };
    } catch (err) {
      console.error('Unlock error:', err);
      return { success: false, error: 'Decryption failed unexpectedly.' };
    }
  };

  const decryptNotesInMemory = async (key: CryptoKey, userId: string) => {
    setIsLoadingNotes(true);
    const encrypted = getEncryptedNotes(userId);
    setRawEncryptedNotes(encrypted);

    const decryptedList: DecryptedNote[] = [];

    for (const note of encrypted) {
      try {
        const content = await decryptAESGCMToString(
          note.encryptedPayload,
          key,
          note.id // additional authenticated data bound to note id!
        );
        decryptedList.push({
          id: note.id,
          userId: note.userId,
          title: note.title,
          category: note.category,
          tags: note.tags,
          content,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
        });
      } catch (err) {
        console.error(`Failed to decrypt note ${note.id}:`, err);
        decryptedList.push({
          id: note.id,
          userId: note.userId,
          title: `${note.title} [INTEGRITY ERROR]`,
          category: note.category,
          tags: note.tags,
          content: '⚠️ Cryptographic validation error: Ciphertext or tag tampered.',
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
        });
      }
    }

    setDecryptedNotes(decryptedList);
    setIsLoadingNotes(false);
  };

  const createNote = async (
    title: string,
    content: string,
    category: string,
    tags: string[]
  ): Promise<{ success: boolean; note?: DecryptedNote; error?: string }> => {
    if (!masterKey || !currentUser) {
      return { success: false, error: 'Vault is locked.' };
    }

    try {
      const noteId = `note-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      // AES-256-GCM encryption with noteId as authenticated additional data (AAD)
      const payload = await encryptAESGCM(content, masterKey, noteId);

      const encryptedRecord: EncryptedNote = {
        id: noteId,
        userId: currentUser.id,
        title: title.trim(),
        category: category.trim() || 'General',
        tags: tags.map((t) => t.trim()).filter(Boolean),
        encryptedPayload: payload,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      saveEncryptedNote(encryptedRecord);

      const newDecrypted: DecryptedNote = {
        id: noteId,
        userId: currentUser.id,
        title: encryptedRecord.title,
        category: encryptedRecord.category,
        tags: encryptedRecord.tags,
        content,
        createdAt: encryptedRecord.createdAt,
        updatedAt: encryptedRecord.updatedAt,
      };

      setDecryptedNotes((prev) => [newDecrypted, ...prev]);
      setRawEncryptedNotes((prev) => [encryptedRecord, ...prev]);

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'NOTE_CREATED',
        severity: 'INFO',
        message: `Encrypted note created: "${title}" (AES-256-GCM)`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'NOTE_CREATE',
        resourceType: 'NOTE',
        resourceId: noteId,
        status: 'SUCCESS',
        details: `Note encrypted with fresh 96-bit nonce and stored in vault`,
      });

      return { success: true, note: newDecrypted };
    } catch (err) {
      console.error('Note encryption failed:', err);
      return { success: false, error: 'Encryption failed.' };
    }
  };

  const editNote = async (
    id: string,
    title: string,
    content: string,
    category: string,
    tags: string[]
  ): Promise<{ success: boolean; error?: string }> => {
    if (!masterKey || !currentUser) {
      return { success: false, error: 'Vault is locked.' };
    }

    try {
      // Re-encrypt with fresh nonce
      const payload = await encryptAESGCM(content, masterKey, id);

      const updatedRecord: EncryptedNote = {
        id,
        userId: currentUser.id,
        title: title.trim(),
        category: category.trim() || 'General',
        tags: tags.map((t) => t.trim()).filter(Boolean),
        encryptedPayload: payload,
        createdAt:
          decryptedNotes.find((n) => n.id === id)?.createdAt ||
          new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      saveEncryptedNote(updatedRecord);

      setDecryptedNotes((prev) =>
        prev.map((n) =>
          n.id === id
            ? {
                ...n,
                title: updatedRecord.title,
                category: updatedRecord.category,
                tags: updatedRecord.tags,
                content,
                updatedAt: updatedRecord.updatedAt,
              }
            : n
        )
      );

      setRawEncryptedNotes((prev) =>
        prev.map((n) => (n.id === id ? updatedRecord : n))
      );

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'NOTE_UPDATED',
        severity: 'INFO',
        message: `Note updated with re-derived 96-bit nonce: "${title}"`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'NOTE_UPDATE',
        resourceType: 'NOTE',
        resourceId: id,
        status: 'SUCCESS',
        details: `Note re-encrypted with fresh IV and updated authentication tag`,
      });

      return { success: true };
    } catch (err) {
      console.error('Note update failed:', err);
      return { success: false, error: 'Encryption failed.' };
    }
  };

  const removeNote = async (
    id: string
  ): Promise<{ success: boolean; error?: string }> => {
    if (!currentUser) return { success: false, error: 'User not authenticated' };

    const deleted = deleteEncryptedNote(id, currentUser.id);
    if (deleted) {
      setDecryptedNotes((prev) => prev.filter((n) => n.id !== id));
      setRawEncryptedNotes((prev) => prev.filter((n) => n.id !== id));

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'NOTE_DELETED',
        severity: 'INFO',
        message: `Encrypted note purged from vault (ID: ${id})`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'NOTE_DELETE',
        resourceType: 'NOTE',
        resourceId: id,
        status: 'SUCCESS',
        details: `Note ciphertext purged from database`,
      });

      return { success: true };
    }
    return { success: false, error: 'Note not found.' };
  };

  const setAutoLockDuration = (minutes: number) => {
    setAutoLockMinutes(minutes);
    setSecondsUntilAutoLock(minutes * 60);
  };

  const getMasterKeyForOperations = () => masterKey;

  const refreshVaultState = () => {
    if (currentUser) {
      const meta = getVaultMetadata(currentUser.id);
      setIsVaultConfigured(!!meta);
      setRawEncryptedNotes(getEncryptedNotes(currentUser.id));
      if (masterKey) {
        decryptNotesInMemory(masterKey, currentUser.id);
      }
    }
  };

  return (
    <VaultContext.Provider
      value={{
        isVaultConfigured,
        isVaultUnlocked: !!masterKey,
        autoLockMinutes,
        secondsUntilAutoLock,
        decryptedNotes,
        rawEncryptedNotes,
        isLoadingNotes,
        setupMasterPassword,
        unlockVault,
        lockVault,
        setAutoLockDuration,
        createNote,
        editNote,
        removeNote,
        getMasterKeyForOperations,
        refreshVaultState,
      }}
    >
      {children}
    </VaultContext.Provider>
  );
};

export function useVault(): VaultContextType {
  const context = useContext(VaultContext);
  if (!context) {
    throw new Error('useVault must be used within a VaultProvider');
  }
  return context;
}
