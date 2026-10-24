/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Header Component
 * Strict Top Bar Contract: Brand Zone — Breadcrumb & Status — Primary Action
 */

import React from 'react';
import {
  Lock,
  Unlock,
  LogOut,
  ShieldAlert,
  Clock,
  ShieldCheck,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useVault } from '../../context/VaultContext';
import { ActiveTab } from '../../types';

interface HeaderProps {
  activeTab: ActiveTab;
  onOpenUnlockModal: () => void;
  onOpenSetupModal: () => void;
}

const TAB_TITLES: Record<ActiveTab, string> = {
  dashboard: 'Security Dashboard',
  notes: 'Encrypted Notes Vault',
  files: 'Encrypted File Vault',
  'tamper-lab': 'Cryptographic & Tamper Lab',
  forensics: 'Digital Forensics & Audit Chain',
  settings: 'Security & Key Settings',
  'college-demo': 'Level 5 Demonstration Guide',
  'code-docs': 'Python Codebase & Architecture Docs',
};

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onOpenUnlockModal,
  onOpenSetupModal,
}) => {
  const { currentUser, logout } = useAuth();
  const {
    isVaultConfigured,
    isVaultUnlocked,
    lockVault,
    secondsUntilAutoLock,
  } = useVault();

  const formatCountdown = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  };

  return (
    <header className="h-16 px-6 bg-[#0f172a] border-b border-slate-800 flex items-center justify-between gap-8 shrink-0 select-none">
      {/* Zone 1: Brand Wordmark */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
          <ShieldCheck className="w-4 h-4" />
        </div>
        <span className="text-base font-bold tracking-tight text-white whitespace-nowrap">
          SecureVaultApp
        </span>
      </div>

      {/* Zone 2: Breadcrumbs & Active Status */}
      <div className="hidden md:flex items-center gap-3 text-xs text-slate-400 whitespace-nowrap overflow-hidden">
        <span className="text-slate-500">Vault Console</span>
        <span className="text-slate-600">/</span>
        <span className="font-medium text-slate-200">{TAB_TITLES[activeTab]}</span>

        {isVaultUnlocked && (
          <>
            <span className="text-slate-600">/</span>
            <div className="flex items-center gap-1.5 text-cyan-400 font-mono tabular-nums">
              <Clock className="w-3.5 h-3.5 text-cyan-500" />
              <span>Auto-lock in {formatCountdown(secondsUntilAutoLock)}</span>
            </div>
          </>
        )}
      </div>

      {/* Zone 3: Primary Action & User Session */}
      <div className="flex items-center gap-3 shrink-0">
        {!isVaultConfigured ? (
          <button
            onClick={onOpenSetupModal}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-cyan-200 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 rounded-lg transition-colors whitespace-nowrap"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
            <span>Initialize Master Key</span>
          </button>
        ) : isVaultUnlocked ? (
          <button
            onClick={() => lockVault('User clicked lock in header')}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-amber-200 bg-amber-950/60 hover:bg-amber-900/80 border border-amber-800/80 rounded-lg transition-colors whitespace-nowrap"
            title="Lock Vault & Purge In-Memory Keys"
          >
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            <span>Lock Vault</span>
          </button>
        ) : (
          <button
            onClick={onOpenUnlockModal}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-emerald-200 bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-800/80 rounded-lg transition-colors whitespace-nowrap"
          >
            <Unlock className="w-3.5 h-3.5 text-emerald-400" />
            <span>Unlock Vault</span>
          </button>
        )}

        <div className="h-4 w-px bg-slate-800 hidden sm:block" />

        {currentUser && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-300 font-medium hidden lg:inline max-w-[140px] truncate">
              {currentUser.email}
            </span>
            <button
              onClick={logout}
              className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
              title="Sign Out"
              aria-label="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
