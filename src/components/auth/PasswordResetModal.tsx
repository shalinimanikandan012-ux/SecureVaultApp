/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Password Recovery Modal
 * Token-based Account Recovery Simulation
 */

import React, { useState } from 'react';
import { KeyRound, Mail, AlertCircle, CheckCircle2, X, ArrowRight, Lock } from 'lucide-react';
import { hashPassword } from '../../services/authService';
import { arrayBufferToBase64, generateRandomBytes } from '../../services/crypto';
import { findUserByEmail, logSecurityEvent, saveUser } from '../../services/storage';

interface PasswordResetModalProps {
  onClose: () => void;
}

export const PasswordResetModal: React.FC<PasswordResetModalProps> = ({ onClose }) => {
  const [step, setStep] = useState<'request' | 'reset'>('request');
  const [email, setEmail] = useState('');
  const [recoveryToken, setRecoveryToken] = useState('');
  const [inputToken, setInputToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [statusMsg, setStatusMsg] = useState<{ type: 'error' | 'success'; text: string } | null>(null);

  const handleRequestToken = (e: React.FormEvent) => {
    e.preventDefault();
    const user = findUserByEmail(email);
    setStatusMsg(null);

    // Generic response regardless of whether email exists to prevent email enumeration
    const generated = `SVA-RST-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    setRecoveryToken(generated);
    setStep('reset');

    if (user) {
      logSecurityEvent({
        userId: user.id,
        userEmail: user.email,
        type: 'SECURITY_SETTINGS_CHANGED',
        severity: 'INFO',
        message: `Password reset token requested for ${user.email}`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);

    if (inputToken.trim().toUpperCase() !== recoveryToken) {
      setStatusMsg({ type: 'error', text: 'Invalid or expired password reset token.' });
      return;
    }

    if (newPassword.length < 10) {
      setStatusMsg({ type: 'error', text: 'Password must be at least 10 characters long.' });
      return;
    }

    if (newPassword !== confirmPassword) {
      setStatusMsg({ type: 'error', text: 'Passwords do not match.' });
      return;
    }

    const user = findUserByEmail(email);
    if (!user) {
      setStatusMsg({ type: 'error', text: 'Account not found.' });
      return;
    }

    const saltBytes = generateRandomBytes(16);
    const newSalt = arrayBufferToBase64(saltBytes);
    const newHash = await hashPassword(newPassword, newSalt);

    const updatedUser = {
      ...user,
      passwordSalt: newSalt,
      passwordHash: newHash,
      failedLoginAttempts: 0,
      lockoutUntil: null,
    };
    saveUser(updatedUser);

    setStatusMsg({
      type: 'success',
      text: 'Account password has been successfully reset! You can now log in with your new credentials.',
    });
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-500 hover:text-slate-300 p-1"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 shrink-0">
            <KeyRound className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Reset Account Password</h2>
            <p className="text-xs text-slate-400">
              {step === 'request'
                ? 'Enter your email to receive a secure single-use reset token'
                : 'Enter reset token and choose a new password'}
            </p>
          </div>
        </div>

        {statusMsg && (
          <div
            className={`mb-4 p-2.5 rounded-lg border text-xs flex items-start gap-2 ${
              statusMsg.type === 'success'
                ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
            }`}
          >
            {statusMsg.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div>{statusMsg.text}</div>
          </div>
        )}

        {step === 'request' ? (
          <form onSubmit={handleRequestToken} className="space-y-4 text-xs">
            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Account Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@securevault.internal"
                  className="w-full pl-9 pr-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg transition-colors flex items-center gap-1.5"
              >
                <span>Generate Reset Token</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleResetPassword} className="space-y-3.5 text-xs">
            {/* Display simulated token banner */}
            <div className="p-3 bg-[#0b1120] border border-slate-800 rounded-lg space-y-1">
              <span className="text-[11px] text-slate-400">
                Single-Use Reset Token (simulated email dispatch):
              </span>
              <div className="font-mono text-cyan-400 text-sm font-bold tracking-wider select-all">
                {recoveryToken}
              </div>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Enter Verification Token
              </label>
              <input
                type="text"
                value={inputToken}
                onChange={(e) => setInputToken(e.target.value.toUpperCase())}
                placeholder="Paste SVA-RST-XXXXXX"
                className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 font-mono"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                New Account Password
              </label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Min. 10 chars"
                className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 font-mono"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Confirm New Password
              </label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm password"
                className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 font-mono"
                required
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
              >
                Close
              </button>
              <button
                type="submit"
                className="py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg transition-colors"
              >
                Set New Password
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
