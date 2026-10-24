/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Vault Unlock & Initialization Modal
 * Enforces Zero-Knowledge Master Password Architecture
 */

import React, { useState } from 'react';
import {
  KeyRound,
  Lock,
  Unlock,
  AlertCircle,
  X,
  Info,
  ShieldCheck,
  ArrowRight,
} from 'lucide-react';
import { useVault } from '../../context/VaultContext';

interface VaultUnlockModalProps {
  mode: 'unlock' | 'setup';
  onClose: () => void;
  onSuccess: () => void;
}

export const VaultUnlockModal: React.FC<VaultUnlockModalProps> = ({
  mode,
  onClose,
  onSuccess,
}) => {
  const { isVaultConfigured, unlockVault, setupMasterPassword } = useVault();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (mode === 'setup') {
      if (password.length < 12) {
        setErrorMsg('Master password must be at least 12 characters.');
        return;
      }
      if (password !== confirmPassword) {
        setErrorMsg('Passwords do not match.');
        return;
      }

      setIsProcessing(true);
      const res = await setupMasterPassword(password);
      setIsProcessing(false);

      if (res.success) {
        onSuccess();
      } else {
        setErrorMsg(res.error || 'Failed to initialize master key.');
      }
    } else {
      setIsProcessing(true);
      const res = await unlockVault(password);
      setIsProcessing(false);

      if (res.success) {
        onSuccess();
      } else {
        setErrorMsg(
          res.error || 'Master password incorrect (AEAD canary tag validation failed).'
        );
      }
    }
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
            {mode === 'setup' ? (
              <ShieldCheck className="w-5 h-5" />
            ) : (
              <Unlock className="w-5 h-5" />
            )}
          </div>
          <div>
            <h2 className="text-base font-bold text-white">
              {mode === 'setup'
                ? 'Initialize Vault Master Key'
                : 'Unlock Encrypted Vault'}
            </h2>
            <p className="text-xs text-slate-400">
              {mode === 'setup'
                ? 'Derive 256-bit AES-GCM key with PBKDF2-SHA256'
                : 'Enter your vault master password to decrypt data'}
            </p>
          </div>
        </div>

        {/* Cryptographic Architecture Note */}
        <div className="mb-4 p-3 rounded-lg bg-cyan-950/30 border border-cyan-800/40 text-xs text-cyan-200/90 flex items-start gap-2.5">
          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed text-[11px]">
            <strong>Zero-Knowledge Principle:</strong> Your master password is never stored
            or transmitted. An in-memory 256-bit AES-GCM key is derived locally and verified
            against an AEAD encrypted canary payload.
          </div>
        </div>

        {errorMsg && (
          <div className="mb-4 p-2.5 rounded-lg bg-rose-950/40 border border-rose-800/80 flex items-start gap-2 text-xs text-rose-300">
            <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
            <div className="leading-snug">{errorMsg}</div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              {mode === 'setup' ? 'Set Master Password' : 'Vault Master Password'}
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <KeyRound className="w-4 h-4" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Min. 12 characters"
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                autoFocus
                required
              />
            </div>
          </div>

          {mode === 'setup' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Confirm Master Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter master password"
                  className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
              </div>
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isProcessing || !password}
              className="py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              {isProcessing ? (
                <span>Deriving PBKDF2 Key...</span>
              ) : mode === 'setup' ? (
                <>
                  <span>Initialize & Derive Key</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              ) : (
                <>
                  <span>Decrypt & Unlock Vault</span>
                  <Unlock className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
