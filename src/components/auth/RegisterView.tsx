/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Registration View
 */

import React, { useState } from 'react';
import { ShieldCheck, Lock, Mail, User, AlertCircle, ArrowRight, Check } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface RegisterViewProps {
  onSwitchToLogin: () => void;
}

export const RegisterView: React.FC<RegisterViewProps> = ({ onSwitchToLogin }) => {
  const { register } = useAuth();
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Password Policy Checks
  const hasMinLength = password.length >= 10;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const passwordsMatch = password.length > 0 && password === confirmPassword;

  // Simple Shannon Entropy estimation
  const calculateEntropy = (str: string) => {
    if (!str) return 0;
    let poolSize = 0;
    if (/[a-z]/.test(str)) poolSize += 26;
    if (/[A-Z]/.test(str)) poolSize += 26;
    if (/[0-9]/.test(str)) poolSize += 10;
    if (/[^A-Za-z0-9]/.test(str)) poolSize += 33;
    const entropyBits = Math.round(str.length * Math.log2(Math.max(poolSize, 1)));
    return Math.min(128, entropyBits);
  };

  const entropy = calculateEntropy(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hasMinLength || !hasUpper || !hasLower || !hasNumber) {
      setErrorMsg('Password must satisfy all security policy requirements.');
      return;
    }
    if (!passwordsMatch) {
      setErrorMsg('Passwords do not match.');
      return;
    }

    setIsSubmitting(true);
    setErrorMsg(null);

    try {
      const res = await register(email, username, password);
      if (!res.success) {
        setErrorMsg(res.error || 'Registration failed.');
      }
    } catch {
      setErrorMsg('An unexpected error occurred during account registration.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-[#0b1120]">
      <div className="w-full max-w-md bg-[#0f172a] border border-slate-800 rounded-xl p-8 shadow-2xl">
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400 mb-3">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Create Account
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise Cybersecurity Identity Provisioning
          </p>
        </div>

        {errorMsg && (
          <div className="mb-4 p-3 rounded-lg bg-rose-950/40 border border-rose-800/80 flex items-start gap-2.5 text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="leading-relaxed">{errorMsg}</div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
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
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Full Name / Operator ID
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <User className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Alice Vance"
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Account Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Min. 10 chars with mixed cases & numbers"
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                required
              />
            </div>
          </div>

          {/* Password Entropy Meter */}
          {password && (
            <div className="space-y-1.5 pt-1">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Entropy Strength:</span>
                <span className="font-mono tabular-nums text-cyan-400 font-medium">
                  {entropy} bits
                </span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${
                    entropy < 40
                      ? 'bg-rose-500'
                      : entropy < 70
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, (entropy / 80) * 100)}%` }}
                />
              </div>

              {/* Policy Criteria */}
              <div className="grid grid-cols-2 gap-1 text-[11px] pt-1 text-slate-400">
                <span className={hasMinLength ? 'text-emerald-400 flex items-center gap-1' : 'flex items-center gap-1'}>
                  {hasMinLength ? <Check className="w-3 h-3" /> : '·'} 10+ characters
                </span>
                <span className={hasUpper ? 'text-emerald-400 flex items-center gap-1' : 'flex items-center gap-1'}>
                  {hasUpper ? <Check className="w-3 h-3" /> : '·'} Uppercase letter
                </span>
                <span className={hasLower ? 'text-emerald-400 flex items-center gap-1' : 'flex items-center gap-1'}>
                  {hasLower ? <Check className="w-3 h-3" /> : '·'} Lowercase letter
                </span>
                <span className={hasNumber ? 'text-emerald-400 flex items-center gap-1' : 'flex items-center gap-1'}>
                  {hasNumber ? <Check className="w-3 h-3" /> : '·'} Number (0-9)
                </span>
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Confirm Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Re-enter password"
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting || !passwordsMatch || !hasMinLength}
            className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
          >
            {isSubmitting ? (
              <span>Provisioning account...</span>
            ) : (
              <>
                <span>Register & Create Vault Identity</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        <div className="mt-5 pt-5 border-t border-slate-800 text-center">
          <p className="text-xs text-slate-400">
            Already have an account?{' '}
            <button
              onClick={onSwitchToLogin}
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
            >
              Sign In
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};
