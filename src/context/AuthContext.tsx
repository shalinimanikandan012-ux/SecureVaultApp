/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Authentication Context
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  AuthResponse,
  completeLoginSession,
  loginUser,
  logoutUser,
  registerUser,
  seedDemoUserIfEmpty,
} from '../services/authService';
import {
  findUserById,
  getActiveSession,
  saveUser,
} from '../services/storage';
import { User } from '../types';

interface AuthContextType {
  currentUser: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, pass: string) => Promise<AuthResponse>;
  register: (email: string, user: string, pass: string) => Promise<AuthResponse>;
  logout: () => Promise<void>;
  completeMfaLogin: (user: User) => Promise<void>;
  updateUserMfaStatus: (
    enabled: boolean,
    secret?: string,
    hashedRecoveryCodes?: string[]
  ) => void;
  refreshUser: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const initAuth = async () => {
    try {
      await seedDemoUserIfEmpty();
      const session = getActiveSession();
      if (session) {
        const user = findUserById(session.userId);
        if (user) {
          setCurrentUser(user);
        }
      }
    } catch (err) {
      console.error('Failed to restore session:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    initAuth();
  }, []);

  const login = async (email: string, pass: string): Promise<AuthResponse> => {
    const res = await loginUser(email, pass);
    if (res.success && res.user && !res.mfaRequired) {
      setCurrentUser(res.user);
    }
    return res;
  };

  const register = async (
    email: string,
    username: string,
    pass: string
  ): Promise<AuthResponse> => {
    const res = await registerUser(email, username, pass);
    if (res.success && res.user) {
      // Automatically log them in after registration
      await completeLoginSession(res.user);
      setCurrentUser(res.user);
    }
    return res;
  };

  const completeMfaLogin = async (user: User) => {
    await completeLoginSession(user);
    setCurrentUser(user);
  };

  const logout = async () => {
    await logoutUser(currentUser);
    setCurrentUser(null);
  };

  const updateUserMfaStatus = (
    enabled: boolean,
    secret?: string,
    hashedRecoveryCodes?: string[]
  ) => {
    if (!currentUser) return;
    const updated: User = {
      ...currentUser,
      mfaEnabled: enabled,
      mfaSecret: secret,
      recoveryCodeHashes: hashedRecoveryCodes || currentUser.recoveryCodeHashes,
    };
    saveUser(updated);
    setCurrentUser(updated);
  };

  const refreshUser = () => {
    if (!currentUser) return;
    const fresh = findUserById(currentUser.id);
    if (fresh) setCurrentUser(fresh);
  };

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        isAuthenticated: !!currentUser,
        isLoading,
        login,
        register,
        logout,
        completeMfaLogin,
        updateUserMfaStatus,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
