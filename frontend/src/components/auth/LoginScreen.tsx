import React, { useState } from 'react';
import { Mail, Lock, Eye, EyeOff, AlertTriangle, Loader2, Shield } from 'lucide-react';
import { AuthLayout } from './AuthLayout';
import { useAuth } from '../../context/AuthContext';
import { useApiErrorHandler } from '../../hooks/useApiErrorHandler';

interface LoginScreenProps {
  onSwitchToRegister: () => void;
  onSwitchToForgotPassword: () => void;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({
  onSwitchToRegister,
  onSwitchToForgotPassword,
}) => {
  const { login, sessionMessage, clearSessionMessage } = useAuth();
  const parseApiError = useApiErrorHandler();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    setErrorMessage(null);
    setIsSubmitting(true);
    try {
      await login(email.trim(), password);
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorMessage(parsed.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const bannerMessage = errorMessage ?? sessionMessage;

  return (
    <AuthLayout>
      {/* Header */}
      <div className="mb-6">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold tracking-wide uppercase bg-brand-soft text-brand border border-brand/20 mb-3 select-none">
          <Shield className="w-3 h-3 text-brand" />
          <span>Forensic Workspace</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Sign in</h1>
        <p className="text-xs text-slate-500 mt-1">
          Enter your credentials to access your forensic intelligence console
        </p>
      </div>

      {bannerMessage && (
        <div
          role="alert"
          className="flex items-start gap-2.5 rounded-xl border border-rose-200 bg-rose-50/80 p-3.5 mb-5 text-rose-800"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
          <p className="text-xs font-medium leading-relaxed">{bannerMessage}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Email Field */}
        <div>
          <label htmlFor="login-email" className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
            Email Address
          </label>
          <div className="relative">
            <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="login-email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                if (sessionMessage) clearSessionMessage();
              }}
              className="w-full pl-10 pr-3.5 py-2.5 text-sm bg-slate-50/70 hover:bg-white border border-slate-200 rounded-xl text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-4 focus:ring-brand/10 focus:border-brand transition-all"
              placeholder="analyst@organization.com"
            />
          </div>
        </div>

        {/* Password Field */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="login-password" className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
              Password
            </label>
            <button
              type="button"
              onClick={onSwitchToForgotPassword}
              className="text-xs font-medium text-brand hover:text-brand-hover hover:underline transition-colors"
            >
              Forgot password?
            </button>
          </div>
          <div className="relative">
            <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="login-password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (sessionMessage) clearSessionMessage();
              }}
              className="w-full pl-10 pr-10 py-2.5 text-sm bg-slate-50/70 hover:bg-white border border-slate-200 rounded-xl text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-4 focus:ring-brand/10 focus:border-brand transition-all font-mono tracking-wide placeholder:font-sans placeholder:tracking-normal"
              placeholder="••••••••••••"
            />
            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-0.5 rounded transition-colors"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Remember device checkbox */}
        <div className="flex items-center justify-between pt-1">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              className="w-4 h-4 rounded border-slate-300 text-brand focus:ring-brand/25 cursor-pointer"
            />
            <span className="text-xs text-slate-600 font-medium">Keep me signed in</span>
          </label>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isSubmitting}
          className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-brand to-[#1D4E9E] hover:from-[#1D4E9E] hover:to-[#163E80] disabled:opacity-60 disabled:cursor-not-allowed text-white text-sm font-semibold py-2.5 px-4 rounded-xl shadow-sm hover:shadow-md hover:shadow-brand/20 active:scale-[0.99] transition-all"
        >
          {isSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
          {isSubmitting ? 'Authenticating…' : 'Sign in'}
        </button>
      </form>

      {/* Switch to Register */}
      <div className="mt-6 pt-5 border-t border-slate-100 text-center">
        <p className="text-xs text-slate-500">
          Don&apos;t have a workspace?{' '}
          <button
            type="button"
            onClick={onSwitchToRegister}
            className="font-semibold text-brand hover:text-brand-hover hover:underline transition-colors"
          >
            Create one
          </button>
        </p>
      </div>
    </AuthLayout>
  );
};

export default LoginScreen;
