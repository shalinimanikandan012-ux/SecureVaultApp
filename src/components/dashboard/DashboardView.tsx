/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Security Dashboard
 * Real calculated metrics, security posture, activity timeline, and tamper status
 */

import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  FileKey,
  FolderLock,
  Lock,
  Unlock,
  Activity,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  GitCommit,
  Clock,
  KeyRound,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useVault } from '../../context/VaultContext';
import { verifyAuditChainIntegrity } from '../../services/auditService';
import { getEncryptedFiles, getSecurityEvents } from '../../services/storage';
import {
  ActiveTab,
  EncryptedFileRecord,
  HashChainVerificationResult,
  SecurityEvent,
} from '../../types';

interface DashboardViewProps {
  onNavigate: (tab: ActiveTab) => void;
  onOpenUnlockModal: () => void;
  onOpenSetupModal: () => void;
  onOpenMfaModal: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  onNavigate,
  onOpenUnlockModal,
  onOpenSetupModal,
  onOpenMfaModal,
}) => {
  const { currentUser } = useAuth();
  const { isVaultConfigured, isVaultUnlocked, rawEncryptedNotes } = useVault();
  const [files, setFiles] = useState<EncryptedFileRecord[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [auditResult, setAuditResult] = useState<HashChainVerificationResult | null>(null);
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);

  useEffect(() => {
    if (currentUser) {
      getEncryptedFiles(currentUser.id).then(setFiles);
      setEvents(getSecurityEvents(currentUser.id));
      verifyChain();
    }
  }, [currentUser]);

  const verifyChain = async () => {
    setIsVerifyingChain(true);
    const res = await verifyAuditChainIntegrity();
    setAuditResult(res);
    setIsVerifyingChain(false);
  };

  const totalVaultSize = files.reduce((acc, f) => acc + f.size, 0);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const formatTimestamp = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return iso;
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner / Welcome & Threat Status */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <span>Security Posture Console</span>
            <span className="text-xs font-normal text-slate-400">· Operator: {currentUser?.username}</span>
          </h1>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>Identity: {currentUser?.email}</span>
            <span aria-hidden="true">·</span>
            <span>Last Login: {currentUser?.lastLoginAt ? formatTimestamp(currentUser.lastLoginAt) : 'Current session'}</span>
            <span aria-hidden="true">·</span>
            <span className="font-mono text-cyan-400">IP: 127.0.0.1</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {!currentUser?.mfaEnabled && (
            <button
              onClick={onOpenMfaModal}
              className="px-3 py-1.5 bg-amber-950/70 hover:bg-amber-900 border border-amber-800/80 text-amber-200 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              <span>Enable MFA Protection</span>
            </button>
          )}

          {!isVaultConfigured ? (
            <button
              onClick={onOpenSetupModal}
              className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5"
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Initialize Master Key</span>
            </button>
          ) : !isVaultUnlocked ? (
            <button
              onClick={onOpenUnlockModal}
              className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Unlock className="w-3.5 h-3.5" />
              <span>Unlock Vault</span>
            </button>
          ) : null}
        </div>
      </div>

      {/* 4-Zone Metric Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Encrypted Notes */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Encrypted Notes</span>
            <FileKey className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">
            {rawEncryptedNotes.length}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500 mt-2">
            <span>AES-256-GCM AEAD</span>
            <span aria-hidden="true">·</span>
            <span>96-bit Nonce</span>
          </div>
        </div>

        {/* Metric 2: Encrypted File Vault */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Encrypted Files</span>
            <FolderLock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">
            {files.length}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500 mt-2">
            <span>{formatBytes(totalVaultSize)} encrypted</span>
            <span aria-hidden="true">·</span>
            <span>IndexedDB</span>
          </div>
        </div>

        {/* Metric 3: MFA Status */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">MFA Security</span>
            {currentUser?.mfaEnabled ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            )}
          </div>
          <div className="text-xl font-bold text-white">
            {currentUser?.mfaEnabled ? (
              <span className="text-emerald-400">Enforced</span>
            ) : (
              <span className="text-amber-400">Not Configured</span>
            )}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500 mt-2">
            <span>RFC 6238 TOTP</span>
            <span aria-hidden="true">·</span>
            <span>{currentUser?.recoveryCodeHashes.length || 0} recovery codes</span>
          </div>
        </div>

        {/* Metric 4: Hash Chain Integrity */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Audit Hash Chain</span>
            <GitCommit className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white">
            {auditResult?.isValid ? (
              <span className="text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" /> Intact
              </span>
            ) : auditResult ? (
              <span className="text-rose-400 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" /> Tampered
              </span>
            ) : (
              <span className="text-slate-400">Verifying...</span>
            )}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-500 mt-2 font-mono tabular-nums">
            <span>{auditResult?.totalChecked || 0} blocks checked</span>
            <span aria-hidden="true">·</span>
            <span>SHA-256</span>
          </div>
        </div>
      </div>

      {/* Main Split: Security Status & Real Event Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Security Controls Status Checklist */}
        <div className="lg:col-span-2 bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>Cryptographic Architecture & Controls</span>
            </h2>
            <button
              onClick={() => onNavigate('tamper-lab')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition-colors"
            >
              <span>Open Cryptographic Lab</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3 text-xs">
            {/* Control 1: Zero-Knowledge Master Key */}
            <div className="p-3 bg-[#0b1120] rounded-lg border border-slate-800/80 flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold text-slate-200">
                  Zero-Knowledge Master Password Derivation
                </div>
                <div className="text-slate-400 text-[11px] mt-0.5 leading-relaxed">
                  PBKDF2-SHA256 with 100,000 rounds and 16-byte cryptographically secure salt. Key
                  lives exclusively in volatile memory; never sent to server.
                </div>
              </div>
              <div className="shrink-0 font-mono text-[11px]">
                {isVaultUnlocked ? (
                  <span className="text-emerald-400 flex items-center gap-1">
                    <Unlock className="w-3.5 h-3.5" /> Active Key
                  </span>
                ) : isVaultConfigured ? (
                  <span className="text-amber-400 flex items-center gap-1">
                    <Lock className="w-3.5 h-3.5" /> Key Purged
                  </span>
                ) : (
                  <span className="text-slate-500">Uninitialized</span>
                )}
              </div>
            </div>

            {/* Control 2: AES-256-GCM Authenticated Encryption */}
            <div className="p-3 bg-[#0b1120] rounded-lg border border-slate-800/80 flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold text-slate-200">
                  Authenticated Encryption with Associated Data (AEAD)
                </div>
                <div className="text-slate-400 text-[11px] mt-0.5 leading-relaxed">
                  AES-256 in Galois/Counter Mode with fresh 96-bit random IVs and 128-bit authentication
                  tags. Prevents bit-flipping and chosen-ciphertext attacks.
                </div>
              </div>
              <div className="shrink-0 font-mono text-[11px] text-emerald-400">
                Enforced
              </div>
            </div>

            {/* Control 3: Tamper-Evident Hash Chain Audit */}
            <div className="p-3 bg-[#0b1120] rounded-lg border border-slate-800/80 flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold text-slate-200">
                  Tamper-Evident SHA-256 Digital Forensics Chain
                </div>
                <div className="text-slate-400 text-[11px] mt-0.5 leading-relaxed">
                  Every user authentication, note mutation, and file upload is recorded with
                  chronological block hashes linked to the previous block hash (H_n = SHA256(H_prev + payload)).
                </div>
              </div>
              <div className="shrink-0 font-mono text-[11px]">
                {auditResult?.isValid ? (
                  <span className="text-emerald-400">Intact</span>
                ) : (
                  <span className="text-rose-400">Compromised</span>
                )}
              </div>
            </div>

            {/* Control 4: Progressive Brute-Force Throttling */}
            <div className="p-3 bg-[#0b1120] rounded-lg border border-slate-800/80 flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold text-slate-200">
                  Login Rate Limiting & Account Lockout
                </div>
                <div className="text-slate-400 text-[11px] mt-0.5 leading-relaxed">
                  Progressive delay after failed attempts. Temporary 15-minute account lockout
                  triggered after 5 consecutive failed authentication requests.
                </div>
              </div>
              <div className="shrink-0 font-mono text-[11px] text-emerald-400">
                Active
              </div>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Real Activity & Security Timeline */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span>Security Events</span>
              </h2>
              <button
                onClick={() => onNavigate('forensics')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
              >
                View Full Audit
              </button>
            </div>

            <div className="space-y-3">
              {events.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-xs">
                  No security events logged yet.
                </div>
              ) : (
                events.slice(0, 5).map((evt) => (
                  <div key={evt.id} className="text-xs space-y-1">
                    <div className="flex items-center justify-between text-slate-400">
                      <span className="font-mono text-[10px] text-cyan-400">
                        {evt.type.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono tabular-nums">
                        {formatTimestamp(evt.timestamp)}
                      </span>
                    </div>
                    <p className="text-slate-300 text-[11px] leading-snug">
                      {evt.message}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
            <span>Audit Trail Recalculation:</span>
            <button
              onClick={verifyChain}
              disabled={isVerifyingChain}
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors disabled:opacity-50"
            >
              {isVerifyingChain ? 'Verifying...' : 'Run Integrity Scan'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
