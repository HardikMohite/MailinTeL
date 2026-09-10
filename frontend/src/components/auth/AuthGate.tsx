import React, { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { LoginScreen } from './LoginScreen';
import { RegisterScreen } from './RegisterScreen';
import { ForgotPasswordScreen } from './ForgotPasswordScreen';

/**
 * Sits above <App/> and is the single source of truth for whether the
 * authenticated shell is shown at all. While the initial session check is
 * running, nothing else renders. Once resolved, either the sign-in/register/recovery
 * flow or the app itself is shown — never both, never a broken in-between
 * state.
 */
export const AuthGate: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const [mode, setMode] = useState<'login' | 'register' | 'forgot-password'>('login');

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#F8FAFC] flex flex-col items-center justify-center gap-3">
        <Loader2 className="w-8 h-8 text-brand animate-spin" />
        <span className="text-xs font-medium text-slate-500 tracking-wide uppercase">Initializing Workspace…</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    if (mode === 'register') {
      return <RegisterScreen onSwitchToLogin={() => setMode('login')} />;
    }
    if (mode === 'forgot-password') {
      return <ForgotPasswordScreen onSwitchToLogin={() => setMode('login')} />;
    }
    return (
      <LoginScreen
        onSwitchToRegister={() => setMode('register')}
        onSwitchToForgotPassword={() => setMode('forgot-password')}
      />
    );
  }

  return <>{children}</>;
};

export default AuthGate;
