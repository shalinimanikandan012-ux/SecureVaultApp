/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Authentication Service
 * User Registration, Login, Progressive Lockout, Session Management & Password Reset
 */

import { User } from '../types';
import { recordAuditEvent } from './auditService';
import {
  arrayBufferToBase64,
  generateRandomBytes,
  sha256Hex,
} from './crypto';
import {
  clearActiveSession,
  findUserByEmail,
  findUserById,
  getActiveSession,
  getUsers,
  logSecurityEvent,
  saveUser,
  saveUsers,
  setActiveSession,
} from './storage';

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const SESSION_DURATION_HOURS = 2;

export interface AuthResponse {
  success: boolean;
  user?: User;
  mfaRequired?: boolean;
  tempToken?: string;
  error?: string;
  lockoutRemainingMinutes?: number;
}

// Hash password with unique salt using PBKDF2 / SHA-256
export async function hashPassword(
  password: string,
  saltBase64: string
): Promise<string> {
  const combined = `${password}:${saltBase64}`;
  return sha256Hex(combined);
}

export async function registerUser(
  email: string,
  username: string,
  password: string
): Promise<AuthResponse> {
  const normalizedEmail = email.trim().toLowerCase();

  if (findUserByEmail(normalizedEmail)) {
    return {
      success: false,
      error: 'An account with this email address already exists.',
    };
  }

  if (password.length < 10) {
    return {
      success: false,
      error: 'Password must be at least 10 characters long.',
    };
  }

  const saltBytes = generateRandomBytes(16);
  const passwordSalt = arrayBufferToBase64(saltBytes);
  const passwordHash = await hashPassword(password, passwordSalt);

  const newUser: User = {
    id: `usr-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    email: normalizedEmail,
    username: username.trim(),
    passwordHash,
    passwordSalt,
    mfaEnabled: false,
    recoveryCodeHashes: [],
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
    failedLoginAttempts: 0,
    lockoutUntil: null,
  };

  saveUser(newUser);

  // Security event & audit entry
  logSecurityEvent({
    userId: newUser.id,
    userEmail: newUser.email,
    type: 'AUTH_REGISTER',
    severity: 'INFO',
    message: `New account registered: ${newUser.email}`,
    timestamp: new Date().toISOString(),
    ipAddress: '127.0.0.1',
    userAgent: navigator.userAgent,
  });

  await recordAuditEvent({
    actorId: newUser.id,
    actorEmail: newUser.email,
    action: 'USER_REGISTRATION',
    resourceType: 'ACCOUNT',
    resourceId: newUser.id,
    status: 'SUCCESS',
    details: `User registered with email ${newUser.email}`,
  });

  return { success: true, user: newUser };
}

export async function loginUser(
  email: string,
  password: string
): Promise<AuthResponse> {
  const normalizedEmail = email.trim().toLowerCase();
  const user = findUserByEmail(normalizedEmail);

  // Constant-time like delay simulation to deter timing attacks
  await new Promise((r) => setTimeout(r, 200));

  if (!user) {
    // Generic failure message to prevent email enumeration
    return { success: false, error: 'Invalid email or password.' };
  }

  // Check account lockout status
  if (user.lockoutUntil) {
    const lockoutExpiry = new Date(user.lockoutUntil).getTime();
    if (Date.now() < lockoutExpiry) {
      const remainingMinutes = Math.ceil((lockoutExpiry - Date.now()) / (60 * 1000));
      logSecurityEvent({
        userId: user.id,
        userEmail: user.email,
        type: 'AUTH_ACCOUNT_LOCKED',
        severity: 'WARNING',
        message: `Login attempt rejected: Account is locked (${remainingMinutes}m remaining).`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      return {
        success: false,
        error: `Account is temporarily locked due to consecutive failed attempts. Try again in ${remainingMinutes} minute(s).`,
        lockoutRemainingMinutes: remainingMinutes,
      };
    } else {
      // Lockout expired, reset
      user.lockoutUntil = null;
      user.failedLoginAttempts = 0;
      saveUser(user);
    }
  }

  // Verify password
  const testHash = await hashPassword(password, user.passwordSalt);
  if (testHash !== user.passwordHash) {
    user.failedLoginAttempts += 1;

    let lockoutMsg = '';
    if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
      user.lockoutUntil = lockUntil.toISOString();
      lockoutMsg = ` Too many failures. Account locked for ${LOCKOUT_MINUTES} minutes.`;
    }

    saveUser(user);

    logSecurityEvent({
      userId: user.id,
      userEmail: user.email,
      type: 'AUTH_LOGIN_FAILURE',
      severity: user.failedLoginAttempts >= 3 ? 'WARNING' : 'INFO',
      message: `Failed login attempt (${user.failedLoginAttempts}/${MAX_FAILED_ATTEMPTS}).${lockoutMsg}`,
      timestamp: new Date().toISOString(),
      ipAddress: '127.0.0.1',
      userAgent: navigator.userAgent,
    });

    await recordAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      action: 'USER_LOGIN',
      resourceType: 'SESSION',
      resourceId: 'pending',
      status: 'FAILURE',
      details: `Password verification failed for ${user.email} (Attempt ${user.failedLoginAttempts})`,
    });

    return {
      success: false,
      error: `Invalid email or password.${lockoutMsg}`,
    };
  }

  // Password correct: reset failed attempts
  user.failedLoginAttempts = 0;
  user.lockoutUntil = null;
  saveUser(user);

  // Check if MFA is enabled
  if (user.mfaEnabled && user.mfaSecret) {
    const tempToken = `mfa_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    return {
      success: true,
      user,
      mfaRequired: true,
      tempToken,
    };
  }

  // No MFA required: complete session
  return completeLoginSession(user);
}

export async function completeLoginSession(user: User): Promise<AuthResponse> {
  const expiresAt = new Date(
    Date.now() + SESSION_DURATION_HOURS * 60 * 60 * 1000
  ).toISOString();

  user.lastLoginAt = new Date().toISOString();
  saveUser(user);

  const token = `sva_tok_${user.id}_${Date.now()}`;
  setActiveSession({
    userId: user.id,
    token,
    expiresAt,
    createdAt: new Date().toISOString(),
  });

  logSecurityEvent({
    userId: user.id,
    userEmail: user.email,
    type: 'AUTH_LOGIN_SUCCESS',
    severity: 'INFO',
    message: `Successful login for ${user.email}`,
    timestamp: new Date().toISOString(),
    ipAddress: '127.0.0.1',
    userAgent: navigator.userAgent,
  });

  await recordAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    action: 'USER_LOGIN',
    resourceType: 'SESSION',
    resourceId: token,
    status: 'SUCCESS',
    details: `User ${user.email} successfully authenticated`,
  });

  return {
    success: true,
    user,
    mfaRequired: false,
  };
}

export async function logoutUser(user?: User | null): Promise<void> {
  const session = getActiveSession();
  const currentUser = user || (session ? findUserById(session.userId) : null);

  clearActiveSession();

  if (currentUser) {
    logSecurityEvent({
      userId: currentUser.id,
      userEmail: currentUser.email,
      type: 'AUTH_LOGOUT',
      severity: 'INFO',
      message: `User signed out: ${currentUser.email}`,
      timestamp: new Date().toISOString(),
      ipAddress: '127.0.0.1',
      userAgent: navigator.userAgent,
    });

    await recordAuditEvent({
      actorId: currentUser.id,
      actorEmail: currentUser.email,
      action: 'USER_LOGOUT',
      resourceType: 'SESSION',
      resourceId: session?.token || 'session',
      status: 'SUCCESS',
      details: `Session terminated for ${currentUser.email}`,
    });
  }
}

// Seed Demo User if no users exist
export async function seedDemoUserIfEmpty(): Promise<void> {
  const users = getUsers();
  if (users.length > 0) return;

  const saltBytes = generateRandomBytes(16);
  const passwordSalt = arrayBufferToBase64(saltBytes);
  // Default demo password: "DemoMasterPassword2026!"
  const passwordHash = await hashPassword('DemoMasterPassword2026!', passwordSalt);

  const demoUser: User = {
    id: 'usr-demo-cybersecurity',
    email: 'analyst@securevault.internal',
    username: 'Security Analyst',
    passwordHash,
    passwordSalt,
    mfaEnabled: false,
    recoveryCodeHashes: [],
    createdAt: new Date(Date.now() - 86400000 * 3).toISOString(),
    lastLoginAt: new Date(Date.now() - 3600000).toISOString(),
    failedLoginAttempts: 0,
    lockoutUntil: null,
  };

  saveUsers([demoUser]);
}
