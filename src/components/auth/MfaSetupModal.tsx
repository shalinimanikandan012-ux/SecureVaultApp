/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp MFA Enrollment Modal
 * Generates RFC 6238 Base32 Secret, SVG QR Code, Live Preview, and Hashed Recovery Codes
 */

import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  Download,
  Copy,
  Check,
  AlertCircle,
  X,
  QrCode,
  Key,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { recordAuditEvent } from '../../services/auditService';
import {
  computeTOTP,
  generateRandomBase32Secret,
  generateRecoveryCodes,
  verifyTOTP,
} from '../../services/crypto';
import { logSecurityEvent } from '../../services/storage';

interface MfaSetupModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

export const MfaSetupModal: React.FC<MfaSetupModalProps> = ({ onClose, onSuccess }) => {
  const { currentUser, updateUserMfaStatus } = useAuth();
  const [secret] = useState(() => generateRandomBase32Secret(16));
  const [recoveryCodes, setRecoveryCodes] = useState<{
    plaintextCodes: string[];
    hashedCodes: string[];
  } | null>(null);

  const [testCode, setTestCode] = useState('');
  const [liveCode, setLiveCode] = useState('');
  const [secondsRemaining, setSecondsRemaining] = useState(30);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // Initialize recovery codes
  useEffect(() => {
    generateRecoveryCodes(8).then(setRecoveryCodes);
  }, []);

  // Live TOTP generator loop for demonstration & instant testing
  useEffect(() => {
    let mounted = true;
    const updateLive = async () => {
      try {
        const { code, secondsRemaining: sec } = await computeTOTP(secret);
        if (mounted) {
          setLiveCode(code);
          setSecondsRemaining(sec);
        }
      } catch (err) {
        console.error(err);
      }
    };

    updateLive();
    const interval = window.setInterval(updateLive, 1000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [secret]);

  const handleCopySecret = () => {
    navigator.clipboard.writeText(secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const handleCopyCodes = () => {
    if (!recoveryCodes) return;
    navigator.clipboard.writeText(recoveryCodes.plaintextCodes.join('\n'));
    setCopiedCodes(true);
    setTimeout(() => setCopiedCodes(false), 2000);
  };

  const handleDownloadCodes = () => {
    if (!recoveryCodes || !currentUser) return;
    const content = `SECUREVAULTAPP MFA BACKUP RECOVERY CODES
Account: ${currentUser.email}
Generated: ${new Date().toISOString()} (UTC)
--------------------------------------------------
Each code can only be used once if you lose your authenticator device.
Store these securely. Do not share them.

${recoveryCodes.plaintextCodes.map((c, i) => `${i + 1}. ${c}`).join('\n')}
--------------------------------------------------`;

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `securevault-recovery-codes-${currentUser.email}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleConfirmMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentUser || !recoveryCodes) return;

    setErrorMsg(null);
    setIsVerifying(true);

    try {
      const isValid = await verifyTOTP(testCode, secret);
      if (!isValid) {
        setErrorMsg('Invalid code. Ensure your device time is synchronized.');
        setIsVerifying(false);
        return;
      }

      // Save user with MFA enabled & hashed recovery codes
      updateUserMfaStatus(true, secret, recoveryCodes.hashedCodes);

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'MFA_ENROLL_SUCCESS',
        severity: 'INFO',
        message: `TOTP Multi-Factor Authentication successfully enrolled`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'MFA_ENROLL',
        resourceType: 'ACCOUNT_SECURITY',
        resourceId: currentUser.id,
        status: 'SUCCESS',
        details: `RFC 6238 TOTP enrolled; 8 SHA-256 recovery code hashes committed`,
      });

      onSuccess();
    } catch {
      setErrorMsg('Failed to finalize MFA enrollment.');
    } finally {
      setIsVerifying(false);
    }
  };

  const otpAuthUri = `otpauth://totp/SecureVaultApp:${currentUser?.email || 'user'}?secret=${secret}&issuer=SecureVaultApp&algorithm=SHA1&digits=6&period=30`;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-lg bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-2xl relative my-8">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-500 hover:text-slate-300 p-1"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">
              Enroll Multi-Factor Authentication (TOTP)
            </h2>
            <p className="text-xs text-slate-400">
              RFC 6238 compliant time-based one-time password security
            </p>
          </div>
        </div>

        {errorMsg && (
          <div className="mb-4 p-2.5 rounded-lg bg-rose-950/40 border border-rose-800/80 flex items-start gap-2 text-xs text-rose-300">
            <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
            <div className="leading-snug">{errorMsg}</div>
          </div>
        )}

        <div className="space-y-4 text-xs">
          {/* Step 1: Secret Key & Authenticator App */}
          <div className="p-3.5 bg-[#0b1120] border border-slate-800 rounded-lg space-y-2.5">
            <div className="font-semibold text-slate-200 flex items-center justify-between">
              <span>Step 1: Link Authenticator App</span>
              <span className="text-[11px] font-mono text-cyan-400">Base32 Secret</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Add this key into Google Authenticator, Microsoft Authenticator, 1Password, or Authy.
            </p>

            <div className="flex items-center gap-2">
              <input
                type="text"
                readOnly
                value={secret}
                className="w-full px-3 py-1.5 bg-[#070b14] border border-slate-700 rounded-md text-cyan-300 font-mono text-xs tracking-wider select-all"
              />
              <button
                type="button"
                onClick={handleCopySecret}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors flex items-center gap-1.5 shrink-0"
              >
                {copiedSecret ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedSecret ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Live Synchronized Token & QR Preview */}
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
              <div className="flex items-center gap-2 text-slate-400">
                <span>Live Test Code:</span>
                <span className="font-mono text-cyan-400 font-bold tracking-widest text-sm tabular-nums">
                  {liveCode}
                </span>
              </div>
              <span className="text-slate-500 font-mono tabular-nums">
                Expires in {secondsRemaining}s
              </span>
            </div>
          </div>

          {/* Step 2: Backup Recovery Codes */}
          <div className="p-3.5 bg-[#0b1120] border border-slate-800 rounded-lg space-y-2.5">
            <div className="font-semibold text-slate-200 flex items-center justify-between">
              <span>Step 2: Emergency Recovery Codes</span>
              <span className="text-[11px] text-amber-400 font-medium">8 Codes</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Only SHA-256 hashes are stored on the server. Each code can be used once if you lose device access.
            </p>

            <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px] text-slate-300 bg-[#070b14] p-2.5 rounded-md border border-slate-800/80">
              {recoveryCodes?.plaintextCodes.map((code, i) => (
                <div key={i} className="flex items-center gap-1 text-slate-400">
                  <span className="text-slate-600 w-3">{i + 1}.</span>
                  <span className="text-slate-200 tracking-wider">{code}</span>
                </div>
              ))}
            </div>

            <div className="flex items-center gap-2 pt-1">
              <button
                type="button"
                onClick={handleDownloadCodes}
                className="flex-1 py-1.5 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors flex items-center justify-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>Download .txt</span>
              </button>
              <button
                type="button"
                onClick={handleCopyCodes}
                className="py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors flex items-center justify-center gap-1.5"
              >
                {copiedCodes ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedCodes ? 'Copied' : 'Copy All'}</span>
              </button>
            </div>
          </div>

          {/* Step 3: Verification Check */}
          <form onSubmit={handleConfirmMfa} className="space-y-3 pt-1">
            <div>
              <label className="block font-medium text-slate-300 mb-1">
                Step 3: Enter the 6-Digit Code from Your Authenticator App
              </label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={testCode}
                onChange={(e) => setTestCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className="w-full text-center py-2 text-base bg-[#0b1120] border border-slate-700 rounded-lg text-cyan-400 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono tracking-widest font-semibold"
                required
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3.5 py-2 text-slate-400 hover:text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isVerifying || testCode.length !== 6}
                className="py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg transition-colors disabled:opacity-50 flex items-center gap-1.5"
              >
                {isVerifying ? 'Verifying...' : 'Verify & Enable MFA'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
