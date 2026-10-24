/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Login View
 */

import React, { useState } from 'react';
import { ShieldCheck, Lock, Mail, AlertCircle, ArrowRight, KeyRound } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { AuthResponse } from '../../services/authService';

interface LoginViewProps {
  onSwitchToRegister: () => void;
  onMfaRequired: (tempToken: string) => void;
  onOpenPasswordReset: () => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  onSwitchToRegister,
  onMfaRequired,
  onOpenPasswordReset,
}) => {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setErrorMsg('Please enter both email and password.');
      return;
    }

    setIsSubmitting(true);
    setErrorMsg(null);

    try {
      const res: AuthResponse = await login(email, password);
      if (!res.success) {
        setErrorMsg(res.error || 'Authentication failed.');
      } else if (res.mfaRequired && res.tempToken) {
        onMfaRequired(res.tempToken);
      }
    } catch {
      setErrorMsg('An unexpected authentication error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleFillDemo = () => {
    setEmail('analyst@securevault.internal');
    setPassword('DemoMasterPassword2026!');
    setErrorMsg(null);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-[#0b1120]">
      <div className="w-full max-w-md bg-[#0f172a] border border-slate-800 rounded-xl p-8 shadow-2xl">
        {/* Brand Lockup */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400 mb-3">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            SecureVaultApp
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise Cybersecurity & Cryptographic Vault
          </p>
        </div>

        {/* Error Callout */}
        {errorMsg && (
          <div className="mb-6 p-3 rounded-lg bg-rose-950/40 border border-rose-800/80 flex items-start gap-2.5 text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="leading-relaxed">{errorMsg}</div>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Work Email
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
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                autoComplete="email"
                required
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-medium text-slate-300">
                Account Password
              </label>
              <button
                type="button"
                onClick={onOpenPasswordReset}
                className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                Forgot password?
              </button>
            </div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
                autoComplete="current-password"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {isSubmitting ? (
              <span>Verifying credentials...</span>
            ) : (
              <>
                <span>Sign In to Vault</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        {/* Demo Account Helper */}
        <div className="mt-6 pt-6 border-t border-slate-800 text-center space-y-3">
          <button
            type="button"
            onClick={handleFillDemo}
            className="w-full py-1.5 px-3 bg-slate-800/80 hover:bg-slate-800 text-slate-300 text-xs rounded-lg border border-slate-700 transition-colors flex items-center justify-center gap-2"
          >
            <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
            <span>Fill Demo Credentials (Level 5 Evaluation)</span>
          </button>

          <p className="text-xs text-slate-400">
            Don't have an account?{' '}
            <button
              onClick={onSwitchToRegister}
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
            >
              Register here
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};
