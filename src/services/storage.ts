/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Storage Service
 * LocalStorage for Metadata & IndexedDB for Encrypted File Storage
 */

import {
  EncryptedFileRecord,
  EncryptedNote,
  SecurityEvent,
  User,
  VaultMetadata,
} from '../types';

const USERS_KEY = 'securevault_users_v1';
const VAULT_META_KEY = 'securevault_meta_v1';
const NOTES_KEY = 'securevault_notes_v1';
const EVENTS_KEY = 'securevault_events_v1';
const ACTIVE_SESSION_KEY = 'securevault_session_v1';

// --- Users Storage ---

export function getUsers(): User[] {
  try {
    const raw = localStorage.getItem(USERS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function saveUsers(users: User[]): void {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

export function findUserByEmail(email: string): User | undefined {
  const users = getUsers();
  return users.find((u) => u.email.toLowerCase() === email.toLowerCase());
}

export function findUserById(id: string): User | undefined {
  const users = getUsers();
  return users.find((u) => u.id === id);
}

export function saveUser(user: User): void {
  const users = getUsers();
  const index = users.findIndex((u) => u.id === user.id);
  if (index >= 0) {
    users[index] = user;
  } else {
    users.push(user);
  }
  saveUsers(users);
}

// --- Active Session ---

export interface SessionData {
  userId: string;
  token: string;
  expiresAt: string;
  createdAt: string;
}

export function getActiveSession(): SessionData | null {
  try {
    const raw = localStorage.getItem(ACTIVE_SESSION_KEY);
    if (!raw) return null;
    const session: SessionData = JSON.parse(raw);
    if (new Date(session.expiresAt).getTime() < Date.now()) {
      localStorage.removeItem(ACTIVE_SESSION_KEY);
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

export function setActiveSession(session: SessionData): void {
  localStorage.setItem(ACTIVE_SESSION_KEY, JSON.stringify(session));
}

export function clearActiveSession(): void {
  localStorage.removeItem(ACTIVE_SESSION_KEY);
}

// --- Vault Metadata ---

export function getVaultMetadata(userId: string): VaultMetadata | null {
  try {
    const raw = localStorage.getItem(`${VAULT_META_KEY}_${userId}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveVaultMetadata(metadata: VaultMetadata): void {
  localStorage.setItem(
    `${VAULT_META_KEY}_${metadata.userId}`,
    JSON.stringify(metadata)
  );
}

// --- Encrypted Notes ---

export function getEncryptedNotes(userId: string): EncryptedNote[] {
  try {
    const raw = localStorage.getItem(NOTES_KEY);
    const allNotes: EncryptedNote[] = raw ? JSON.parse(raw) : [];
    return allNotes.filter((n) => n.userId === userId);
  } catch {
    return [];
  }
}

export function saveEncryptedNote(note: EncryptedNote): void {
  const raw = localStorage.getItem(NOTES_KEY);
  const allNotes: EncryptedNote[] = raw ? JSON.parse(raw) : [];
  const index = allNotes.findIndex((n) => n.id === note.id);
  if (index >= 0) {
    allNotes[index] = note;
  } else {
    allNotes.unshift(note);
  }
  localStorage.setItem(NOTES_KEY, JSON.stringify(allNotes));
}

export function deleteEncryptedNote(id: string, userId: string): boolean {
  const raw = localStorage.getItem(NOTES_KEY);
  const allNotes: EncryptedNote[] = raw ? JSON.parse(raw) : [];
  const filtered = allNotes.filter((n) => !(n.id === id && n.userId === userId));
  localStorage.setItem(NOTES_KEY, JSON.stringify(filtered));
  return allNotes.length !== filtered.length;
}

// --- Security Events ---

export function getSecurityEvents(userId?: string): SecurityEvent[] {
  try {
    const raw = localStorage.getItem(EVENTS_KEY);
    const allEvents: SecurityEvent[] = raw ? JSON.parse(raw) : [];
    if (userId) {
      return allEvents.filter((e) => e.userId === userId);
    }
    return allEvents;
  } catch {
    return [];
  }
}

export function logSecurityEvent(event: Omit<SecurityEvent, 'id'>): SecurityEvent {
  const raw = localStorage.getItem(EVENTS_KEY);
  const allEvents: SecurityEvent[] = raw ? JSON.parse(raw) : [];
  const newEvent: SecurityEvent = {
    ...event,
    id: `sec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
  };

  allEvents.unshift(newEvent);
  // Cap at 200 events
  if (allEvents.length > 200) {
    allEvents.length = 200;
  }
  localStorage.setItem(EVENTS_KEY, JSON.stringify(allEvents));
  return newEvent;
}

// --- IndexedDB for Encrypted Files (bypasses 5MB localStorage limits safely) ---

const IDB_NAME = 'SecureVaultApp_DB';
const IDB_VERSION = 1;
const IDB_FILES_STORE = 'encrypted_files';

function openIndexedDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(IDB_NAME, IDB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(IDB_FILES_STORE)) {
        db.createObjectStore(IDB_FILES_STORE, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function getEncryptedFiles(userId: string): Promise<EncryptedFileRecord[]> {
  const db = await openIndexedDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_FILES_STORE, 'readonly');
    const store = tx.objectStore(IDB_FILES_STORE);
    const request = store.getAll();
    request.onsuccess = () => {
      const all: EncryptedFileRecord[] = request.result || [];
      resolve(all.filter((f) => f.userId === userId));
    };
    request.onerror = () => reject(request.error);
  });
}

export async function saveEncryptedFile(file: EncryptedFileRecord): Promise<void> {
  const db = await openIndexedDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_FILES_STORE, 'readwrite');
    const store = tx.objectStore(IDB_FILES_STORE);
    const request = store.put(file);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function deleteEncryptedFile(id: string, userId: string): Promise<boolean> {
  const db = await openIndexedDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_FILES_STORE, 'readwrite');
    const store = tx.objectStore(IDB_FILES_STORE);
    const getReq = store.get(id);
    getReq.onsuccess = () => {
      const record = getReq.result as EncryptedFileRecord | undefined;
      if (!record || record.userId !== userId) {
        resolve(false);
        return;
      }
      const delReq = store.delete(id);
      delReq.onsuccess = () => resolve(true);
      delReq.onerror = () => reject(delReq.error);
    };
    getReq.onerror = () => reject(getReq.error);
  });
}

// Reset/clear all storage (for tests and clean demo state)
export async function clearAllVaultData(): Promise<void> {
  localStorage.clear();
  try {
    const db = await openIndexedDB();
    const tx = db.transaction(IDB_FILES_STORE, 'readwrite');
    tx.objectStore(IDB_FILES_STORE).clear();
  } catch (err) {
    console.error('Failed to clear IndexedDB:', err);
  }
}
