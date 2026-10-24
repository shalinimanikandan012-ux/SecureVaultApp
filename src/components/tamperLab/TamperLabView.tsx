/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Cryptography & Tamper Verification Lab
 * Live Interactive Cryptographic Validation Tests for College Assessment & Examiners
 */

import React, { useState } from 'react';
import {
  Binary,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  ShieldAlert,
  Flame,
  ArrowRight,
  Info,
} from 'lucide-react';
import {
  getAuditLogEntries,
  tamperAuditLogEntry,
  verifyAuditChainIntegrity,
} from '../../services/auditService';
import {
  arrayBufferToBase64,
  computeTOTP,
  decryptAESGCMToString,
  deriveKeyFromPassword,
  encryptAESGCM,
  flipBitInBase64,
  generateRandomBase32Secret,
  generateRandomBytes,
  PBKDF2_ITERATIONS,
  verifyTOTP,
} from '../../services/crypto';
import { EncryptedPayload, HashChainVerificationResult } from '../../types';

export const TamperLabView: React.FC = () => {
  // --- Test Suite 1: AES-256-GCM Bit-Flipping & AEAD Integrity ---
  const [plaintextInput, setPlaintextInput] = useState(
    'TOP_SECRET_CLEARANCE_PAYLOAD: Authorization Granted for Operation Cryptographic Shield.'
  );
  const [labKey, setLabKey] = useState<CryptoKey | null>(null);
  const [labKeyPassword, setLabKeyPassword] = useState('LabMasterKey2026!');
  const [encryptedPayload, setEncryptedPayload] = useState<EncryptedPayload | null>(null);
  const [decryptionResult, setDecryptionResult] = useState<{
    success: boolean;
    output?: string;
    error?: string;
    executionTimeMs?: number;
  } | null>(null);
  const [isTamperedCiphertext, setIsTamperedCiphertext] = useState(false);
  const [isTamperedTag, setIsTamperedTag] = useState(false);

  // --- Test Suite 2: Nonce Uniqueness ---
  const [nonceTestResults, setNonceTestResults] = useState<{
    run1: { nonce: string; ciphertext: string };
    run2: { nonce: string; ciphertext: string };
    noncesIdentical: boolean;
    ciphertextsIdentical: boolean;
  } | null>(null);

  // --- Test Suite 3: Audit Hash Chain Tamper Simulation ---
  const [auditTamperResult, setAuditTamperResult] = useState<HashChainVerificationResult | null>(null);
  const [tamperedBlockIndex, setTamperedBlockIndex] = useState<number | null>(null);

  // --- Test Suite 4: TOTP Verification ---
  const [totpSecret, setTotpSecret] = useState(() => generateRandomBase32Secret(16));
  const [totpTestCode, setTotpTestCode] = useState('');
  const [totpVerificationOutcome, setTotpVerificationOutcome] = useState<boolean | null>(null);

  // Execute AES-GCM Encryption
  const handleEncrypt = async () => {
    try {
      const salt = generateRandomBytes(16);
      const key = await deriveKeyFromPassword(labKeyPassword, salt, PBKDF2_ITERATIONS);
      setLabKey(key);

      const payload = await encryptAESGCM(plaintextInput, key, 'LAB_RECORD_01');
      setEncryptedPayload(payload);
      setDecryptionResult(null);
      setIsTamperedCiphertext(false);
      setIsTamperedTag(false);
    } catch (err) {
      console.error(err);
    }
  };

  // Execute AES-GCM Decryption
  const handleDecrypt = async () => {
    if (!encryptedPayload || !labKey) return;
    const start = performance.now();
    try {
      const result = await decryptAESGCMToString(
        encryptedPayload,
        labKey,
        'LAB_RECORD_01'
      );
      const elapsed = Math.round(performance.now() - start);
      setDecryptionResult({
        success: true,
        output: result,
        executionTimeMs: elapsed,
      });
    } catch (err: unknown) {
      const elapsed = Math.round(performance.now() - start);
      const errorMsg =
        err instanceof Error
          ? `${err.name}: ${err.message}`
          : 'OperationError: Authentication tag verification failed. Ciphertext or tag was modified.';
      setDecryptionResult({
        success: false,
        error: errorMsg,
        executionTimeMs: elapsed,
      });
    }
  };

  // Flip bit in Ciphertext
  const handleTamperCiphertext = () => {
    if (!encryptedPayload) return;
    const tamperedCiphertext = flipBitInBase64(encryptedPayload.ciphertext, 2);
    setEncryptedPayload({
      ...encryptedPayload,
      ciphertext: tamperedCiphertext,
    });
    setIsTamperedCiphertext(true);
    setDecryptionResult(null);
  };

  // Flip bit in Authentication Tag
  const handleTamperTag = () => {
    if (!encryptedPayload) return;
    const tamperedTag = flipBitInBase64(encryptedPayload.tag, 0);
    setEncryptedPayload({
      ...encryptedPayload,
      tag: tamperedTag,
    });
    setIsTamperedTag(true);
    setDecryptionResult(null);
  };

  // Test Nonce Uniqueness
  const handleTestNonceUniqueness = async () => {
    const salt = generateRandomBytes(16);
    const key = await deriveKeyFromPassword('SamePasswordKey', salt, 50000);
    const text = 'IDENTICAL_PLAINTEXT_PAYLOAD';

    const p1 = await encryptAESGCM(text, key);
    const p2 = await encryptAESGCM(text, key);

    setNonceTestResults({
      run1: { nonce: p1.nonce, ciphertext: p1.ciphertext },
      run2: { nonce: p2.nonce, ciphertext: p2.ciphertext },
      noncesIdentical: p1.nonce === p2.nonce,
      ciphertextsIdentical: p1.ciphertext === p2.ciphertext,
    });
  };

  // Deliberately tamper with an audit chain block
  const handleTamperAuditBlock = (index: number) => {
    tamperAuditLogEntry(
      index,
      'MALICIOUS_INJECTION: Actor altered event details to erase evidence.'
    );
    setTamperedBlockIndex(index);
    setAuditTamperResult(null);
  };

  // Run audit chain verification
  const handleVerifyAuditChain = async () => {
    const res = await verifyAuditChainIntegrity();
    setAuditTamperResult(res);
  };

  // Verify TOTP token
  const handleVerifyTotp = async () => {
    const valid = await verifyTOTP(totpTestCode, totpSecret);
    setTotpVerificationOutcome(valid);
  };

  const handleGenerateLiveTotp = async () => {
    const { code } = await computeTOTP(totpSecret);
    setTotpTestCode(code);
    setTotpVerificationOutcome(null);
  };

  const auditEntries = getAuditLogEntries();

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          <Binary className="w-5 h-5 text-cyan-400" />
          <span>Cryptographic & Tamper Verification Laboratory</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Interactive evaluation harness for Level 5 Cybersecurity project grading.
          Directly verifies AEAD authenticated encryption, bit-level tampering resistance, nonce uniqueness, and hash chain integrity.
        </p>
      </div>

      {/* Lab 1: Real AES-256-GCM Bit-Flipping & AEAD Integrity Check */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Experiment 1: AES-256-GCM Bit-Flipping & AEAD Integrity Failure
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Demonstrates that tampering with even 1 single bit in the ciphertext or authentication tag causes decryption to cryptographically fail.
            </p>
          </div>
          <span className="font-mono text-xs text-cyan-400">RFC 5116 AEAD</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Plaintext Input */}
          <div className="space-y-2">
            <label className="block text-slate-300 font-medium">Plaintext Payload</label>
            <textarea
              rows={3}
              value={plaintextInput}
              onChange={(e) => setPlaintextInput(e.target.value)}
              className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={handleEncrypt}
                className="py-1.5 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Encrypt (AES-256-GCM)</span>
              </button>
            </div>
          </div>

          {/* Ciphertext & Tag Representation */}
          <div className="space-y-2">
            <label className="block text-slate-300 font-medium">
              Encrypted Payload Components (Base64)
            </label>
            {encryptedPayload ? (
              <div className="p-3 bg-[#070b14] rounded-lg border border-slate-800 font-mono text-[11px] space-y-1.5">
                <div>
                  <span className="text-slate-500">Nonce (96-bit IV): </span>
                  <span className="text-cyan-400 break-all select-all">
                    {encryptedPayload.nonce}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Authentication Tag (128-bit): </span>
                  <span
                    className={`break-all select-all ${
                      isTamperedTag ? 'text-rose-400 font-bold bg-rose-950/40 px-1 rounded' : 'text-amber-400'
                    }`}
                  >
                    {encryptedPayload.tag}
                  </span>
                  {isTamperedTag && <span className="text-rose-400 ml-1.5">[TAMPERED]</span>}
                </div>
                <div>
                  <span className="text-slate-500">Ciphertext: </span>
                  <span
                    className={`break-all select-all ${
                      isTamperedCiphertext
                        ? 'text-rose-400 font-bold bg-rose-950/40 px-1 rounded'
                        : 'text-slate-300'
                    }`}
                  >
                    {encryptedPayload.ciphertext.slice(0, 50)}...
                  </span>
                  {isTamperedCiphertext && (
                    <span className="text-rose-400 ml-1.5">[TAMPERED 1 BIT]</span>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-6 text-center border border-dashed border-slate-800 rounded-lg text-slate-500">
                Click "Encrypt" to generate AES-256-GCM ciphertext.
              </div>
            )}
          </div>
        </div>

        {/* Action Buttons: Tamper vs Decrypt */}
        {encryptedPayload && (
          <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2">
              <button
                onClick={handleTamperCiphertext}
                className="py-1.5 px-3 bg-amber-950/80 hover:bg-amber-900 border border-amber-800/80 text-amber-200 rounded-lg transition-colors flex items-center gap-1.5"
                title="Flips 1 bit in ciphertext to test integrity failure"
              >
                <Flame className="w-3.5 h-3.5 text-amber-400" />
                <span>Tamper 1 Bit in Ciphertext</span>
              </button>

              <button
                onClick={handleTamperTag}
                className="py-1.5 px-3 bg-amber-950/80 hover:bg-amber-900 border border-amber-800/80 text-amber-200 rounded-lg transition-colors flex items-center gap-1.5"
                title="Flips 1 bit in auth tag to test AEAD rejection"
              >
                <Flame className="w-3.5 h-3.5 text-amber-400" />
                <span>Tamper Auth Tag</span>
              </button>

              <button
                onClick={handleEncrypt}
                className="py-1.5 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors flex items-center gap-1"
                title="Reset to untampered"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset</span>
              </button>
            </div>

            <button
              onClick={handleDecrypt}
              className="py-1.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold rounded-lg transition-colors flex items-center gap-1.5"
            >
              <span>Attempt Decryption</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Decryption Result */}
        {decryptionResult && (
          <div
            className={`p-3.5 rounded-lg border text-xs ${
              decryptionResult.success
                ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-300'
                : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
            }`}
          >
            <div className="flex items-center justify-between font-semibold mb-1">
              <div className="flex items-center gap-2">
                {decryptionResult.success ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Integrity Verified: Decryption Succeeded ({decryptionResult.executionTimeMs}ms)</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span>Cryptographic Integrity Check Failed ({decryptionResult.executionTimeMs}ms)</span>
                  </>
                )}
              </div>
              <span className="font-mono text-[11px]">
                {decryptionResult.success ? 'AEAD Tag Validated' : 'OperationError: Tag Mismatch'}
              </span>
            </div>
            <p className="font-mono text-[11px] break-all mt-1">
              {decryptionResult.success
                ? `Decrypted: "${decryptionResult.output}"`
                : `Error: ${decryptionResult.error}`}
            </p>
          </div>
        )}
      </div>

      {/* Lab 2: Nonce Uniqueness Verification */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Experiment 2: Nonce (IV) Uniqueness & Indistinguishability
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Demonstrates that encrypting the exact same plaintext twice produces two completely unique nonces and ciphertexts.
            </p>
          </div>
          <button
            onClick={handleTestNonceUniqueness}
            className="py-1 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors"
          >
            Run Nonce Test
          </button>
        </div>

        {nonceTestResults && (
          <div className="space-y-2 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
              <div className="p-3 bg-[#070b14] border border-slate-800 rounded-lg space-y-1">
                <span className="text-cyan-400 font-semibold">Run #1:</span>
                <div>
                  <span className="text-slate-500">Nonce: </span>
                  <span className="text-slate-200 break-all">{nonceTestResults.run1.nonce}</span>
                </div>
                <div>
                  <span className="text-slate-500">Ciphertext: </span>
                  <span className="text-slate-400 break-all">{nonceTestResults.run1.ciphertext.slice(0, 36)}...</span>
                </div>
              </div>

              <div className="p-3 bg-[#070b14] border border-slate-800 rounded-lg space-y-1">
                <span className="text-cyan-400 font-semibold">Run #2:</span>
                <div>
                  <span className="text-slate-500">Nonce: </span>
                  <span className="text-slate-200 break-all">{nonceTestResults.run2.nonce}</span>
                </div>
                <div>
                  <span className="text-slate-500">Ciphertext: </span>
                  <span className="text-slate-400 break-all">{nonceTestResults.run2.ciphertext.slice(0, 36)}...</span>
                </div>
              </div>
            </div>

            <div className="p-2.5 bg-emerald-950/30 border border-emerald-800/80 rounded-lg text-emerald-300 text-[11px] flex items-center justify-between">
              <span>
                Nonces Identical: <strong>{nonceTestResults.noncesIdentical ? 'YES (CRITICAL FLAW)' : 'NO (SECURE UNIQUE IVs)'}</strong>
              </span>
              <span>
                Ciphertexts Identical: <strong>{nonceTestResults.ciphertextsIdentical ? 'YES' : 'NO (INDISTINGUISHABLE)'}</strong>
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Lab 3: Digital Forensics Hash Chain Tamper Injection */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Experiment 3: Cryptographic Audit Hash Chain Tamper Injection
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulates a malicious database administrator modifying an existing audit record. The verification algorithm detects the discrepancy immediately.
            </p>
          </div>
          <button
            onClick={handleVerifyAuditChain}
            className="py-1 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors"
          >
            Run Forensic Scan
          </button>
        </div>

        <div className="space-y-3 text-xs">
          {auditEntries.length === 0 ? (
            <div className="text-slate-500 py-3 text-center">
              No audit logs present. Perform an action (create note or file) to generate blocks.
            </div>
          ) : (
            <div className="space-y-2">
              <span className="text-slate-300 font-medium">
                Select a block to inject tampering into:
              </span>
              <div className="flex flex-wrap gap-2">
                {auditEntries.slice(0, 5).map((entry) => (
                  <button
                    key={entry.id}
                    onClick={() => handleTamperAuditBlock(entry.index)}
                    className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-[11px] font-mono transition-colors"
                  >
                    Block #{entry.index} ({entry.action})
                  </button>
                ))}
              </div>
            </div>
          )}

          {tamperedBlockIndex !== null && (
            <div className="p-3 bg-amber-950/40 border border-amber-800/80 rounded-lg text-amber-300 text-xs flex items-center justify-between">
              <span>
                Tamper injected into Block #{tamperedBlockIndex}. Click "Run Forensic Scan" to test tamper detection.
              </span>
            </div>
          )}

          {auditTamperResult && (
            <div
              className={`p-3.5 rounded-lg border text-xs ${
                auditTamperResult.isValid
                  ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
              }`}
            >
              <div className="flex items-center gap-2 font-semibold">
                {auditTamperResult.isValid ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Cryptographic Audit Chain Intact: {auditTamperResult.totalChecked} blocks verified</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span>Tamper Detected at Block #{auditTamperResult.brokenAtIndex}!</span>
                  </>
                )}
              </div>
              <p className="mt-1 text-[11px] leading-relaxed">
                {auditTamperResult.reason}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Lab 4: TOTP Authenticator Simulation */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Experiment 4: RFC 6238 TOTP Drift & Verification Test
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Validates 30-second time-step counters with dynamic HMAC-SHA1 truncation and $\pm 1$ step drift window tolerance.
            </p>
          </div>
          <span className="font-mono text-xs text-cyan-400">RFC 6238 / RFC 4226</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Base32 Secret</label>
            <input
              type="text"
              readOnly
              value={totpSecret}
              className="w-full px-2.5 py-1.5 bg-[#0b1120] border border-slate-700 rounded text-cyan-300 font-mono text-xs"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Enter 6-Digit Code</label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={totpTestCode}
                onChange={(e) => setTotpTestCode(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                maxLength={6}
                className="w-full px-2.5 py-1.5 bg-[#0b1120] border border-slate-700 rounded text-slate-100 font-mono text-center tracking-widest text-xs"
              />
              <button
                type="button"
                onClick={handleGenerateLiveTotp}
                className="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded whitespace-nowrap text-[11px]"
              >
                Insert Live Code
              </button>
            </div>
          </div>

          <div className="flex items-end">
            <button
              onClick={handleVerifyTotp}
              className="w-full py-1.5 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg transition-colors"
            >
              Verify Token
            </button>
          </div>
        </div>

        {totpVerificationOutcome !== null && (
          <div
            className={`p-2.5 rounded-lg border text-xs flex items-center gap-2 ${
              totpVerificationOutcome
                ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-300'
                : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
            }`}
          >
            {totpVerificationOutcome ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>TOTP Code Verified Successfully (RFC 6238 Compliant)</span>
              </>
            ) : (
              <>
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>Verification Failed: Invalid code or outside acceptable drift window</span>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
