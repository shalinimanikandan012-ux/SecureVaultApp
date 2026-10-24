/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Main Application Entry Point
 * Enterprise Cybersecurity & Cryptographic Vault
 */

import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { VaultProvider, useVault } from './context/VaultContext';
import { ActiveTab, User } from './types';

// Common Components
import { Header } from './components/common/Header';
import { Sidebar } from './components/common/Sidebar';

// Auth Components
import { LoginView } from './components/auth/LoginView';
import { RegisterView } from './components/auth/RegisterView';
import { MfaModal } from './components/auth/MfaModal';
import { MfaSetupModal } from './components/auth/MfaSetupModal';
import { PasswordResetModal } from './components/auth/PasswordResetModal';

// Vault Modals
import { VaultUnlockModal } from './components/vault/VaultUnlockModal';

// Views
import { DashboardView } from './components/dashboard/DashboardView';
import { NotesVaultView } from './components/notes/NotesVaultView';
import { FileVaultView } from './components/files/FileVaultView';
import { TamperLabView } from './components/tamperLab/TamperLabView';
import { ForensicsView } from './components/forensics/ForensicsView';
import { SecuritySettingsView } from './components/settings/SecuritySettingsView';
import { CollegeDemoView } from './components/demo/CollegeDemoView';
import { CodeDocsView } from './components/codeDocs/CodeDocsView';
import { findUserById } from './services/storage';

const AppContent: React.FC = () => {
  const { currentUser, isAuthenticated, isLoading } = useAuth();
  const { isVaultConfigured } = useVault();

  // Navigation State
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [authView, setAuthView] = useState<'login' | 'register'>('login');

  // Modals
  const [isUnlockModalOpen, setIsUnlockModalOpen] = useState(false);
  const [unlockModalMode, setUnlockModalMode] = useState<'unlock' | 'setup'>('unlock');
  const [isMfaSetupOpen, setIsMfaSetupOpen] = useState(false);
  const [isPasswordResetOpen, setIsPasswordResetOpen] = useState(false);

  // Login MFA Challenge State
  const [mfaChallengeUser, setMfaChallengeUser] = useState<User | null>(null);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#0b1120] flex items-center justify-center text-slate-400 text-xs font-mono">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span>Initializing Cryptographic Subsystem...</span>
        </div>
      </div>
    );
  }

  // Not authenticated: Show Login or Register View
  if (!isAuthenticated || !currentUser) {
    return (
      <>
        {authView === 'login' ? (
          <LoginView
            onSwitchToRegister={() => setAuthView('register')}
            onMfaRequired={(tempToken) => {
              // Find user with pending MFA
              const user = currentUser || findUserById(tempToken.split('_')[1]);
              if (user) setMfaChallengeUser(user);
            }}
            onOpenPasswordReset={() => setIsPasswordResetOpen(true)}
          />
        ) : (
          <RegisterView onSwitchToLogin={() => setAuthView('login')} />
        )}

        {/* MFA Challenge Modal during Login */}
        {mfaChallengeUser && (
          <MfaModal
            user={mfaChallengeUser}
            onSuccess={() => setMfaChallengeUser(null)}
            onCancel={() => setMfaChallengeUser(null)}
          />
        )}

        {/* Password Reset Modal */}
        {isPasswordResetOpen && (
          <PasswordResetModal onClose={() => setIsPasswordResetOpen(false)} />
        )}
      </>
    );
  }

  // Authenticated: Enterprise Dashboard Layout
  return (
    <div className="min-h-screen bg-[#0b1120] text-slate-100 flex flex-col antialiased">
      {/* 3-Zone Top Bar Contract */}
      <Header
        activeTab={activeTab}
        onOpenUnlockModal={() => {
          setUnlockModalMode(isVaultConfigured ? 'unlock' : 'setup');
          setIsUnlockModalOpen(true);
        }}
        onOpenSetupModal={() => {
          setUnlockModalMode('setup');
          setIsUnlockModalOpen(true);
        }}
      />

      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Navigation */}
        <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#0b1120]">
          {activeTab === 'dashboard' && (
            <DashboardView
              onNavigate={setActiveTab}
              onOpenUnlockModal={() => {
                setUnlockModalMode('unlock');
                setIsUnlockModalOpen(true);
              }}
              onOpenSetupModal={() => {
                setUnlockModalMode('setup');
                setIsUnlockModalOpen(true);
              }}
              onOpenMfaModal={() => setIsMfaSetupOpen(true)}
            />
          )}

          {activeTab === 'notes' && (
            <NotesVaultView
              onOpenUnlockModal={() => {
                setUnlockModalMode('unlock');
                setIsUnlockModalOpen(true);
              }}
              onOpenSetupModal={() => {
                setUnlockModalMode('setup');
                setIsUnlockModalOpen(true);
              }}
            />
          )}

          {activeTab === 'files' && (
            <FileVaultView
              onOpenUnlockModal={() => {
                setUnlockModalMode('unlock');
                setIsUnlockModalOpen(true);
              }}
              onOpenSetupModal={() => {
                setUnlockModalMode('setup');
                setIsUnlockModalOpen(true);
              }}
            />
          )}

          {activeTab === 'tamper-lab' && <TamperLabView />}

          {activeTab === 'forensics' && <ForensicsView />}

          {activeTab === 'settings' && (
            <SecuritySettingsView
              onOpenMfaModal={() => setIsMfaSetupOpen(true)}
              onOpenUnlockModal={() => {
                setUnlockModalMode('unlock');
                setIsUnlockModalOpen(true);
              }}
              onOpenSetupModal={() => {
                setUnlockModalMode('setup');
                setIsUnlockModalOpen(true);
              }}
            />
          )}

          {activeTab === 'college-demo' && (
            <CollegeDemoView
              onNavigate={setActiveTab}
              onOpenUnlockModal={() => {
                setUnlockModalMode('unlock');
                setIsUnlockModalOpen(true);
              }}
              onOpenSetupModal={() => {
                setUnlockModalMode('setup');
                setIsUnlockModalOpen(true);
              }}
              onOpenMfaModal={() => setIsMfaSetupOpen(true)}
            />
          )}

          {activeTab === 'code-docs' && <CodeDocsView />}
        </main>
      </div>

      {/* Vault Master Password Unlock / Setup Modal */}
      {isUnlockModalOpen && (
        <VaultUnlockModal
          mode={unlockModalMode}
          onClose={() => setIsUnlockModalOpen(false)}
          onSuccess={() => setIsUnlockModalOpen(false)}
        />
      )}

      {/* MFA Enrollment Modal */}
      {isMfaSetupOpen && (
        <MfaSetupModal
          onClose={() => setIsMfaSetupOpen(false)}
          onSuccess={() => setIsMfaSetupOpen(false)}
        />
      )}
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <VaultProvider>
        <AppContent />
      </VaultProvider>
    </AuthProvider>
  );
}
