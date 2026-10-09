import React, { useState } from 'react';
import { User, Lock, Eye, EyeOff, AlertTriangle, Loader2, ArrowRight } from 'lucide-react';
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

  const [identifier, setIdentifier] = useState('');
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
      await login(identifier.trim(), password);
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorMessage(parsed.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const bannerMessage = errorMessage ?? sessionMessage;

  return (
    <AuthLayout
      heroHeadline={
        <>
          <span className="block text-slate-950 font-black">Every Email Has a DNA.</span>
          <span className="block text-blue-600 font-black mt-3 sm:mt-3.5">Trace the Origin.</span>
        </>
      }
      heroSubtitle="Unmask true physical sender origins, deconstruct multi-hop forwarding footprints, and analyze 5-strand forensic DNA in real time."
      features={[
        'Passive Origin & Geo-Forwarding Footprint Triangulation',
        '5-Strand Composite Email DNA Fingerprinting',
        'Autonomous AI Threat Reasoning & Attack Categorization',
        'Cross-Tenant Campaign Correlation & Graph Intelligence',
      ]}
    >
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">Welcome back</h1>
        <p className="text-sm text-slate-500 mt-1.5">
          Sign in to access your forensic investigation workspace.
        </p>
      </div>

      {bannerMessage && (
        <div
          role="alert"
          className="flex items-start gap-2.5 rounded-xl border border-rose-200 bg-rose-50/90 p-3.5 mb-6 text-rose-800"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
          <p className="text-xs font-medium leading-relaxed">{bannerMessage}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Email or Username Field */}
        <div>
          <label htmlFor="login-identifier" className="block text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-2">
            Email or Username
          </label>
          <div className="relative">
            <User className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="login-identifier"
              type="text"
              autoComplete="username"
              required
              value={identifier}
              onChange={(e) => {
                setIdentifier(e.target.value);
                if (sessionMessage) clearSessionMessage();
              }}
              className="w-full pl-10 pr-3.5 py-3 text-sm bg-white hover:border-slate-400 focus:bg-white border border-slate-300 rounded-xl text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-600 transition-all shadow-2xs"
              placeholder="analyst@mailintel.org or username"
            />
          </div>
        </div>

        {/* Password Field */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="login-password" className="block text-[11px] font-bold text-slate-700 uppercase tracking-wider">
              Password
            </label>
            <button
              type="button"
              onClick={onSwitchToForgotPassword}
              className="text-xs font-semibold text-blue-600 hover:text-blue-700 hover:underline transition-colors"
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
              className="w-full pl-10 pr-10 py-3 text-sm bg-white hover:border-slate-400 focus:bg-white border border-slate-300 rounded-xl text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-600 transition-all font-mono tracking-wide placeholder:font-sans placeholder:tracking-normal shadow-2xs"
              placeholder="••••••••••••"
            />
            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-0.5 rounded transition-colors"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Remember device checkbox */}
        <div className="flex items-center justify-between pt-0.5">
          <label className="flex items-center gap-2.5 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500/25 cursor-pointer"
            />
            <span className="text-xs text-slate-600 font-medium">Keep me signed in for 30 days</span>
          </label>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isSubmitting}
          className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-60 disabled:cursor-not-allowed text-white text-sm font-semibold py-3 px-4 rounded-xl shadow-md shadow-blue-500/25 active:scale-[0.99] transition-all cursor-pointer"
        >
          {isSubmitting ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <>
              <span>Sign In</span>
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </form>

      {/* Switch to Register */}
      <div className="mt-8 pt-6 border-t border-slate-100 text-center">
        <p className="text-xs text-slate-500">
          Don&apos;t have an account?{' '}
          <button
            type="button"
            onClick={onSwitchToRegister}
            className="font-semibold text-blue-600 hover:text-blue-700 hover:underline transition-colors cursor-pointer"
          >
            Create one
          </button>
        </p>
      </div>
    </AuthLayout>
  );
};

export default LoginScreen;
