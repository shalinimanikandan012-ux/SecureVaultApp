/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Level 5 College Demonstration Guide
 * Interactive 12-Step Evaluation Walkthrough for Examiners & Reviewers
 */

import React, { useState } from 'react';
import {
  CheckCircle2,
  Circle,
  Award,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  FileKey,
  FolderLock,
  Binary,
  GitCommit,
  RotateCcw,
} from 'lucide-react';
import { ActiveTab, DemoStep } from '../../types';

interface CollegeDemoViewProps {
  onNavigate: (tab: ActiveTab) => void;
  onOpenUnlockModal: () => void;
  onOpenSetupModal: () => void;
  onOpenMfaModal: () => void;
}

const DEFAULT_STEPS: DemoStep[] = [
  {
    step: 1,
    title: 'User Registration & Salt Generation',
    rubricArea: 'Authentication & Hashing',
    description:
      'Register a new account or inspect the salted PBKDF2/Argon2 password hash in local database storage.',
    completed: true,
  },
  {
    step: 2,
    title: 'Sign In & Rate Limiting Protection',
    rubricArea: 'Threat Mitigation',
    description:
      'Sign in with credentials. Demonstrates progressive throttling and 15-minute account lockout after 5 consecutive failures.',
    completed: true,
  },
  {
    step: 3,
    title: 'Configure Multi-Factor Authentication (TOTP)',
    rubricArea: 'MFA & Recovery',
    description:
      'Enroll in RFC 6238 TOTP using the interactive secret key generator and export 8 SHA-256 hashed emergency recovery codes.',
    completed: false,
  },
  {
    step: 4,
    title: 'Derive Master Key & Canary Verification',
    rubricArea: 'Zero-Knowledge Cryptography',
    description:
      'Initialize and unlock the vault with a master password distinct from the login password. Derives an AES-256-GCM key in volatile memory.',
    completed: false,
  },
  {
    step: 5,
    title: 'Create & Save Authenticated Encrypted Note',
    rubricArea: 'AEAD Encryption',
    description:
      'Create a confidential note. Inspect the raw Base64 ciphertext, fresh 96-bit nonce, and 128-bit authentication tag.',
    completed: false,
  },
  {
    step: 6,
    title: 'Upload File to Encrypted File Vault',
    rubricArea: 'Secure Storage & Chunking',
    description:
      'Upload a document or key file. Computes SHA-256 checksum and commits AES-256-GCM ciphertext to IndexedDB.',
    completed: false,
  },
  {
    step: 7,
    title: 'Lock Vault & Verify Memory Purge',
    rubricArea: 'Key Lifecycle',
    description:
      'Lock the vault manually or wait for the inactivity auto-lock countdown. Verifies that decrypted data and keys are wiped from memory.',
    completed: false,
  },
  {
    step: 8,
    title: 'Unlock Vault & Verify File Download Integrity',
    rubricArea: 'Integrity Verification',
    description:
      'Re-enter master password, decrypt stored notes, and download the encrypted file. The system checks the post-decryption SHA-256 checksum.',
    completed: false,
  },
  {
    step: 9,
    title: 'Review Security Event Activity Timeline',
    rubricArea: 'Monitoring & Logging',
    description:
      'Inspect chronological security alerts (logins, vault locks, key derivation events) with UTC timestamps and actor metadata.',
    completed: false,
  },
  {
    step: 10,
    title: 'Verify Audit Log Cryptographic Hash Chain',
    rubricArea: 'Digital Forensics',
    description:
      'Run the cryptographic verification scan to recalculate and validate all block hashes linked by H_n = SHA256(H_{n-1} + payload).',
    completed: false,
  },
  {
    step: 11,
    title: 'Test Cryptographic Lab & Tamper Detection',
    rubricArea: 'Adversarial Testing',
    description:
      'Flip 1 bit in a ciphertext or audit block in the Cryptographic Lab to observe authentic AEAD tag mismatch rejection.',
    completed: false,
  },
  {
    step: 12,
    title: 'Export Forensic Audit Report & Sign Out',
    rubricArea: 'Reporting & Session Teardown',
    description:
      'Download the Markdown audit report with cryptographic verification seals, then terminate session.',
    completed: false,
  },
];

export const CollegeDemoView: React.FC<CollegeDemoViewProps> = ({
  onNavigate,
  onOpenUnlockModal,
  onOpenSetupModal,
  onOpenMfaModal,
}) => {
  const [steps, setSteps] = useState<DemoStep[]>(() => {
    try {
      const saved = localStorage.getItem('securevault_demo_checklist');
      return saved ? JSON.parse(saved) : DEFAULT_STEPS;
    } catch {
      return DEFAULT_STEPS;
    }
  });

  const toggleStep = (stepNumber: number) => {
    const updated = steps.map((s) =>
      s.step === stepNumber ? { ...s, completed: !s.completed } : s
    );
    setSteps(updated);
    localStorage.setItem('securevault_demo_checklist', JSON.stringify(updated));
  };

  const handleResetChecklist = () => {
    setSteps(DEFAULT_STEPS);
    localStorage.removeItem('securevault_demo_checklist');
  };

  const completedCount = steps.filter((s) => s.completed).length;
  const progressPercent = Math.round((completedCount / steps.length) * 100);

  const handleJumpToStep = (stepNumber: number) => {
    switch (stepNumber) {
      case 1:
      case 2:
        onNavigate('settings');
        break;
      case 3:
        onOpenMfaModal();
        break;
      case 4:
        onOpenUnlockModal();
        break;
      case 5:
        onNavigate('notes');
        break;
      case 6:
        onNavigate('files');
        break;
      case 7:
        onOpenUnlockModal();
        break;
      case 8:
        onNavigate('files');
        break;
      case 9:
        onNavigate('dashboard');
        break;
      case 10:
        onNavigate('forensics');
        break;
      case 11:
        onNavigate('tamper-lab');
        break;
      case 12:
        onNavigate('forensics');
        break;
      default:
        onNavigate('dashboard');
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header Banner */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Award className="w-5 h-5 text-cyan-400" />
            <span>Level 5 College Cybersecurity Assessment Guide</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Follow this 12-step guided demonstration workflow to verify all cybersecurity, cryptographic, and digital forensic criteria.
          </p>
        </div>

        <button
          onClick={handleResetChecklist}
          className="py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition-colors flex items-center gap-1.5 shrink-0"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Rubric Checklist</span>
        </button>
      </div>

      {/* Progress Card */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-300 font-semibold">
            Demonstration Progress: {completedCount} / {steps.length} Steps Completed
          </span>
          <span className="font-mono text-cyan-400 font-bold tabular-nums">
            {progressPercent}%
          </span>
        </div>
        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-cyan-500 transition-all duration-300 rounded-full"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      {/* Checklist Grid */}
      <div className="space-y-3">
        {steps.map((item) => (
          <div
            key={item.step}
            className={`p-4 rounded-xl border transition-colors flex items-start justify-between gap-4 ${
              item.completed
                ? 'bg-emerald-950/20 border-emerald-800/50'
                : 'bg-[#0f172a] border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start gap-3 min-w-0">
              <button
                onClick={() => toggleStep(item.step)}
                className="mt-0.5 text-slate-400 hover:text-cyan-400 transition-colors shrink-0"
                title={item.completed ? 'Mark incomplete' : 'Mark completed'}
              >
                {item.completed ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <Circle className="w-5 h-5 text-slate-600" />
                )}
              </button>

              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-cyan-400 font-bold">
                    Step {item.step}.
                  </span>
                  <h3 className="text-sm font-semibold text-white truncate">
                    {item.title}
                  </h3>
                  <span className="text-[11px] text-slate-400 font-medium">
                    · {item.rubricArea}
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {item.description}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0 self-center">
              <button
                onClick={() => handleJumpToStep(item.step)}
                className="py-1 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg transition-colors flex items-center gap-1.5"
              >
                <span>Navigate</span>
                <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
