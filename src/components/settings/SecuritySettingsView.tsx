/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Security & Key Settings
 */

import React, { useState } from 'react';
import {
  Settings,
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  Clock,
  Lock,
  Unlock,
  AlertTriangle,
  RotateCcw,
  Check,
  Key,
  Smartphone,
  HardDrive,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useVault } from '../../context/VaultContext';
import { recordAuditEvent } from '../../services/auditService';
import { hashPassword } from '../../services/authService';
import { arrayBufferToBase64, generateRandomBytes } from '../../services/crypto';
import {
  clearActiveSession,
  clearAllVaultData,
  getActiveSession,
  logSecurityEvent,
  saveUser,
} from '../../services/storage';

interface SecuritySettingsViewProps {
  onOpenMfaModal: () => void;
  onOpenUnlockModal: () => void;
  onOpenSetupModal: () => void;
}

export const SecuritySettingsView: React.FC<SecuritySettingsViewProps> = ({
  onOpenMfaModal,
  onOpenUnlockModal,
  onOpenSetupModal,
}) => {
  const { currentUser, updateUserMfaStatus, logout } = useAuth();
  const {
    isVaultConfigured,
    isVaultUnlocked,
    autoLockMinutes,
    setAutoLockDuration,
    lockVault,
  } = useVault();

  // Change Password State
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordStatus, setPasswordStatus] = useState<{
    success: boolean;
    msg: string;
  } | null>(null);

  // Active Session info
  const session = getActiveSession();

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentUser) return;

    if (newPassword.length < 10) {
      setPasswordStatus({
        success: false,
        msg: 'New password must be at least 10 characters long.',
      });
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordStatus({
        success: false,
        msg: 'New passwords do not match.',
      });
      return;
    }

    // Verify old password
    const testHash = await hashPassword(oldPassword, currentUser.passwordSalt);
    if (testHash !== currentUser.passwordHash) {
      setPasswordStatus({
        success: false,
        msg: 'Current account password incorrect.',
      });
      return;
    }

    // Derive new password hash with fresh salt
    const saltBytes = generateRandomBytes(16);
    const newSalt = arrayBufferToBase64(saltBytes);
    const newHash = await hashPassword(newPassword, newSalt);

    const updatedUser = {
      ...currentUser,
      passwordSalt: newSalt,
      passwordHash: newHash,
    };
    saveUser(updatedUser);

    logSecurityEvent({
      userId: currentUser.id,
      userEmail: currentUser.email,
      type: 'SECURITY_SETTINGS_CHANGED',
      severity: 'INFO',
      message: `Account authentication password changed`,
      timestamp: new Date().toISOString(),
      ipAddress: '127.0.0.1',
      userAgent: navigator.userAgent,
    });

    await recordAuditEvent({
      actorId: currentUser.id,
      actorEmail: currentUser.email,
      action: 'PASSWORD_CHANGE',
      resourceType: 'ACCOUNT_SECURITY',
      resourceId: currentUser.id,
      status: 'SUCCESS',
      details: `Account login password updated with fresh random salt`,
    });

    setPasswordStatus({
      success: true,
      msg: 'Account login password updated successfully.',
    });
    setOldPassword('');
    setNewPassword('');
    setConfirmPassword('');
  };

  const handleDisableMfa = async () => {
    if (!currentUser) return;
    if (confirm('Are you sure you want to disable Multi-Factor Authentication?')) {
      updateUserMfaStatus(false, undefined, []);

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'SECURITY_SETTINGS_CHANGED',
        severity: 'WARNING',
        message: `MFA protection was disabled by operator`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'MFA_DISABLE',
        resourceType: 'ACCOUNT_SECURITY',
        resourceId: currentUser.id,
        status: 'SUCCESS',
        details: `Two-factor authentication disabled by user`,
      });
    }
  };

  const handleFactoryReset = async () => {
    if (
      confirm(
        'DANGER: This will wipe all local data, vault keys, notes, files, and audit logs. Continue?'
      )
    ) {
      await clearAllVaultData();
      window.location.reload();
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Title */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-400" />
          <span>Security & Key Management Settings</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Configure authentication credentials, zero-knowledge master key policies, session lifetimes, and multi-factor authentication.
        </p>
      </div>

      {/* Grid of Security Setting Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Section 1: Multi-Factor Authentication */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Smartphone className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">Two-Factor Authentication (TOTP)</h2>
              </div>
              {currentUser?.mfaEnabled ? (
                <span className="text-emerald-400 text-xs font-semibold flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" /> Enforced
                </span>
              ) : (
                <span className="text-amber-400 text-xs font-semibold flex items-center gap-1">
                  <ShieldAlert className="w-3.5 h-3.5" /> Disabled
                </span>
              )}
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Protects account sign-in with an RFC 6238 time-based authenticator (Google Authenticator, Authy, or 1Password) and 8 emergency recovery codes.
            </p>

            {currentUser?.mfaEnabled && (
              <div className="p-3 bg-[#0b1120] rounded-lg border border-slate-800 text-xs space-y-1">
                <div className="flex items-center justify-between text-slate-400">
                  <span>Active Recovery Codes:</span>
                  <span className="font-mono text-cyan-400 font-bold tabular-nums">
                    {currentUser.recoveryCodeHashes.length} remaining
                  </span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Hash Algorithm:</span>
                  <span className="font-mono text-slate-300">HMAC-SHA1 / SHA-256 Hashes</span>
                </div>
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-slate-800 mt-4 flex items-center gap-2">
            {currentUser?.mfaEnabled ? (
              <button
                onClick={handleDisableMfa}
                className="py-1.5 px-3 bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs rounded-lg transition-colors"
              >
                Disable 2FA
              </button>
            ) : (
              <button
                onClick={onOpenMfaModal}
                className="py-1.5 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors"
              >
                Enroll Authenticator App
              </button>
            )}
          </div>
        </div>

        {/* Section 2: Vault Master Key & Auto-Lock */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">Vault Inactivity Auto-Lock</h2>
              </div>
              <div className="font-mono text-xs">
                {isVaultUnlocked ? (
                  <span className="text-emerald-400 flex items-center gap-1">
                    <Unlock className="w-3.5 h-3.5" /> Unlocked
                  </span>
                ) : (
                  <span className="text-amber-400 flex items-center gap-1">
                    <Lock className="w-3.5 h-3.5" /> Locked
                  </span>
                )}
              </div>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Automatically purges the AES-256-GCM master key and decrypted notes from memory after
              user inactivity (no mouse movements or keystrokes).
            </p>

            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-300">
                Inactivity Timeout Duration
              </label>
              <select
                value={autoLockMinutes}
                onChange={(e) => setAutoLockDuration(Number(e.target.value))}
                className="w-full bg-[#0b1120] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value={1}>1 minute (High Security)</option>
                <option value={5}>5 minutes</option>
                <option value={10}>10 minutes (Recommended)</option>
                <option value={30}>30 minutes</option>
                <option value={60}>60 minutes</option>
              </select>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between">
            {isVaultUnlocked ? (
              <button
                onClick={() => lockVault('Operator manual lock in settings')}
                className="py-1.5 px-3 bg-amber-950/70 hover:bg-amber-900 border border-amber-800 text-amber-200 text-xs rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Lock Vault Now</span>
              </button>
            ) : isVaultConfigured ? (
              <button
                onClick={onOpenUnlockModal}
                className="py-1.5 px-3 bg-emerald-950/70 hover:bg-emerald-900 border border-emerald-800 text-emerald-200 text-xs rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Unlock className="w-3.5 h-3.5" />
                <span>Unlock Vault</span>
              </button>
            ) : (
              <button
                onClick={onOpenSetupModal}
                className="py-1.5 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
              >
                Initialize Master Key
              </button>
            )}
          </div>
        </div>

        {/* Section 3: Change Account Login Password */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white">Change Account Password</h2>
          </div>

          {passwordStatus && (
            <div
              className={`p-2.5 rounded-lg border text-xs ${
                passwordStatus.success
                  ? 'bg-emerald-950/30 border-emerald-800 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              {passwordStatus.msg}
            </div>
          )}

          <form onSubmit={handleChangePassword} className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-300 mb-1">Current Password</label>
              <input
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 mb-1">New Password (Min. 10 chars)</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 mb-1">Confirm New Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <button
              type="submit"
              className="py-1.5 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg transition-colors"
            >
              Update Password
            </button>
          </form>
        </div>

        {/* Section 4: Active Session & Factory Reset */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <Clock className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white">Active Session Details</h2>
            </div>

            <div className="p-3 bg-[#0b1120] rounded-lg border border-slate-800 font-mono text-[11px] space-y-1.5 text-slate-300">
              <div>
                <span className="text-slate-500">Session ID: </span>
                <span className="text-cyan-400">{session?.token ? `${session.token.slice(0, 20)}...` : 'None'}</span>
              </div>
              <div>
                <span className="text-slate-500">Created: </span>
                <span>{session?.createdAt || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-500">Expires: </span>
                <span>{session?.expiresAt || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-500">User Agent: </span>
                <span className="text-[10px] text-slate-400 truncate block">
                  {navigator.userAgent}
                </span>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 space-y-2">
            <div className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider">
              Danger Zone
            </div>
            <p className="text-[11px] text-slate-400">
              Clears all local storage, IndexedDB files, and cryptographic keys to start fresh.
            </p>
            <button
              type="button"
              onClick={handleFactoryReset}
              className="py-1.5 px-3 bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs rounded-lg transition-colors"
            >
              Clear All Data & Reset Application
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
