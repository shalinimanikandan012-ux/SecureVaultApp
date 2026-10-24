/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp MFA Challenge Modal
 * Handles TOTP RFC 6238 Token Verification and Single-Use Recovery Code Fallback
 */

import React, { useState } from 'react';
import { ShieldCheck, Key, AlertCircle, ArrowRight, X } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { recordAuditEvent } from '../../services/auditService';
import { sha256Hex, verifyTOTP } from '../../services/crypto';
import { logSecurityEvent, saveUser } from '../../services/storage';
import { User } from '../../types';

interface MfaModalProps {
  user: User;
  onSuccess: () => void;
  onCancel: () => void;
}

export const MfaModal: React.FC<MfaModalProps> = ({ user, onSuccess, onCancel }) => {
  const { completeMfaLogin } = useAuth();
  const [token, setToken] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setIsVerifying(true);

    try {
      if (isRecoveryMode) {
        // Recovery code verification
        const formattedCode = recoveryCode.trim().toUpperCase();
        const codeHash = await sha256Hex(formattedCode);
        const index = user.recoveryCodeHashes.indexOf(codeHash);

        if (index === -1) {
          setErrorMsg('Invalid or already consumed backup recovery code.');
          logSecurityEvent({
            userId: user.id,
            userEmail: user.email,
            type: 'MFA_CHALLENGE_FAILURE',
            severity: 'WARNING',
            message: `Invalid recovery code attempted for ${user.email}`,
            timestamp: new Date().toISOString(),
            ipAddress: '127.0.0.1',
            userAgent: navigator.userAgent,
          });
          setIsVerifying(false);
          return;
        }

        // Consume single-use recovery code
        const updatedHashes = [...user.recoveryCodeHashes];
        updatedHashes.splice(index, 1);
        const updatedUser = { ...user, recoveryCodeHashes: updatedHashes };
        saveUser(updatedUser);

        logSecurityEvent({
          userId: user.id,
          userEmail: user.email,
          type: 'MFA_RECOVERY_USED',
          severity: 'WARNING',
          message: `Single-use recovery code consumed. ${updatedHashes.length} codes remaining.`,
          timestamp: new Date().toISOString(),
          ipAddress: '127.0.0.1',
          userAgent: navigator.userAgent,
        });

        await recordAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          action: 'MFA_RECOVERY_LOGIN',
          resourceType: 'SESSION',
          resourceId: user.id,
          status: 'SUCCESS',
          details: `User authenticated via backup recovery code (${updatedHashes.length} left)`,
        });

        await completeMfaLogin(updatedUser);
        onSuccess();
      } else {
        // Standard TOTP verification
        if (!user.mfaSecret) {
          setErrorMsg('MFA configuration missing for user.');
          setIsVerifying(false);
          return;
        }

        const isValid = await verifyTOTP(token, user.mfaSecret);
        if (!isValid) {
          setErrorMsg('Invalid 6-digit authentication code. Check your authenticator app.');
          logSecurityEvent({
            userId: user.id,
            userEmail: user.email,
            type: 'MFA_CHALLENGE_FAILURE',
            severity: 'WARNING',
            message: `TOTP verification failure for ${user.email}`,
            timestamp: new Date().toISOString(),
            ipAddress: '127.0.0.1',
            userAgent: navigator.userAgent,
          });

          await recordAuditEvent({
            actorId: user.id,
            actorEmail: user.email,
            action: 'MFA_VERIFY',
            resourceType: 'SESSION',
            resourceId: user.id,
            status: 'FAILURE',
            details: `Invalid TOTP token supplied`,
          });

          setIsVerifying(false);
          return;
        }

        logSecurityEvent({
          userId: user.id,
          userEmail: user.email,
          type: 'MFA_CHALLENGE_SUCCESS',
          severity: 'INFO',
          message: `TOTP 2-Factor challenge satisfied for ${user.email}`,
          timestamp: new Date().toISOString(),
          ipAddress: '127.0.0.1',
          userAgent: navigator.userAgent,
        });

        await recordAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          action: 'MFA_VERIFY',
          resourceType: 'SESSION',
          resourceId: user.id,
          status: 'SUCCESS',
          details: `Time-based one-time password verified against RFC 6238`,
        });

        await completeMfaLogin(user);
        onSuccess();
      }
    } catch (err) {
      console.error('MFA error:', err);
      setErrorMsg('Failed to process authentication verification.');
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-sm bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-2xl relative">
        <button
          onClick={onCancel}
          className="absolute top-4 right-4 text-slate-500 hover:text-slate-300 p-1"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="text-center mb-5">
          <div className="inline-flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400 mb-2">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-bold text-white">Two-Factor Authentication</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {isRecoveryMode
              ? 'Enter an unused 10-character recovery code'
              : 'Enter the 6-digit code from your authenticator app'}
          </p>
        </div>

        {errorMsg && (
          <div className="mb-4 p-2.5 rounded-lg bg-rose-950/40 border border-rose-800/80 flex items-start gap-2 text-xs text-rose-300">
            <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
            <div className="leading-snug">{errorMsg}</div>
          </div>
        )}

        <form onSubmit={handleVerify} className="space-y-4">
          {isRecoveryMode ? (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Backup Recovery Code
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Key className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={recoveryCode}
                  onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())}
                  placeholder="XXXXX-XXXXX"
                  className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono tracking-wider"
                  autoFocus
                  required
                />
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                TOTP Security Code
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={token}
                onChange={(e) => setToken(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                className="w-full text-center py-2.5 px-3 text-lg bg-[#0b1120] border border-slate-700 rounded-lg text-cyan-400 placeholder-slate-600 focus:outline-none focus:border-cyan-500 tracking-widest font-mono font-semibold"
                autoFocus
                required
              />
            </div>
          )}

          <button
            type="submit"
            disabled={isVerifying || (isRecoveryMode ? !recoveryCode : token.length !== 6)}
            className="w-full py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {isVerifying ? (
              <span>Verifying code...</span>
            ) : (
              <>
                <span>Authenticate & Proceed</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        <div className="mt-4 pt-4 border-t border-slate-800 text-center">
          <button
            type="button"
            onClick={() => {
              setIsRecoveryMode(!isRecoveryMode);
              setErrorMsg(null);
            }}
            className="text-xs text-slate-400 hover:text-cyan-400 transition-colors"
          >
            {isRecoveryMode ? 'Use Authenticator App Code' : 'Lost device? Use a backup recovery code'}
          </button>
        </div>
      </div>
    </div>
  );
};
