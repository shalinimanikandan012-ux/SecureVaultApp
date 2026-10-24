/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Sidebar Navigation
 */

import React from 'react';
import {
  LayoutDashboard,
  FileKey,
  FolderLock,
  Binary,
  GitCommit,
  Settings,
  CheckCircle2,
  Code2,
  Lock,
  Unlock,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useVault } from '../../context/VaultContext';
import { ActiveTab } from '../../types';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
}

interface NavItem {
  id: ActiveTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab }) => {
  const { currentUser } = useAuth();
  const { isVaultUnlocked, isVaultConfigured, decryptedNotes } = useVault();

  const navItems: NavItem[] = [
    {
      id: 'dashboard',
      label: 'Security Dashboard',
      icon: LayoutDashboard,
    },
    {
      id: 'notes',
      label: 'Encrypted Notes',
      icon: FileKey,
      badge: isVaultUnlocked ? `${decryptedNotes.length}` : undefined,
    },
    {
      id: 'files',
      label: 'Secure File Vault',
      icon: FolderLock,
    },
    {
      id: 'tamper-lab',
      label: 'Cryptographic Lab',
      icon: Binary,
    },
    {
      id: 'forensics',
      label: 'Forensics & Audit',
      icon: GitCommit,
    },
    {
      id: 'college-demo',
      label: 'Assessment Demo',
      icon: CheckCircle2,
    },
    {
      id: 'code-docs',
      label: 'Python Code & Docs',
      icon: Code2,
    },
    {
      id: 'settings',
      label: 'Security Settings',
      icon: Settings,
    },
  ];

  return (
    <aside className="w-64 bg-[#090e1a] border-r border-slate-800 flex flex-col justify-between shrink-0 select-none">
      <div className="p-4 space-y-6">
        {/* Navigation Section */}
        <div>
          <div className="px-3 pb-2 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
            Enterprise Vault
          </div>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-lg transition-colors text-left ${
                    isActive
                      ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-800/60 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span className="truncate">{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className="font-mono text-[11px] text-slate-400 font-semibold tabular-nums">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Security Posture Status Footer */}
      <div className="p-4 border-t border-slate-800/80 bg-[#070b14] space-y-2.5 text-xs">
        <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
          Security Controls
        </div>

        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px]">Vault Status</span>
          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            {isVaultUnlocked ? (
              <>
                <Unlock className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400">Unlocked</span>
              </>
            ) : isVaultConfigured ? (
              <>
                <Lock className="w-3 h-3 text-amber-400" />
                <span className="text-amber-400">Locked</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-3 h-3 text-cyan-400" />
                <span className="text-cyan-400">Uninitialized</span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px]">MFA Protection</span>
          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            {currentUser?.mfaEnabled ? (
              <>
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400">Enforced</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-3 h-3 text-slate-500" />
                <span className="text-slate-500">Disabled</span>
              </>
            )}
          </div>
        </div>

        <div className="pt-1 border-t border-slate-800/50 flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>AES-256-GCM</span>
          <span className="text-slate-600">·</span>
          <span>SHA-256 Chain</span>
        </div>
      </div>
    </aside>
  );
};
