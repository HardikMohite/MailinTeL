import React, { useMemo, useState } from 'react';
import { Mail, Lock, Eye, EyeOff, User, UserPlus, AlertTriangle, Loader2, Check } from 'lucide-react';
import { AuthLayout } from './AuthLayout';
import { useAuth } from '../../context/AuthContext';
import { useApiErrorHandler, PydanticErrorDetail } from '../../hooks/useApiErrorHandler';
import { ValidationErrorBanner } from '../errors/ValidationErrorBanner';
import { checkPasswordStrength } from '../../utils/passwordStrength';

interface RegisterScreenProps {
  onSwitchToLogin: () => void;
}

const STRENGTH_LABEL = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
const STRENGTH_COLOR = [
  'bg-rose-500',
  'bg-amber-500',
  'bg-yellow-500',
  'bg-brand',
  'bg-emerald-500',
];

export const RegisterScreen: React.FC<RegisterScreenProps> = ({ onSwitchToLogin }) => {
  const { register } = useAuth();
  const parseApiError = useApiErrorHandler();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [touchedPassword, setTouchedPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [validationDetails, setValidationDetails] = useState<PydanticErrorDetail[] | undefined>(undefined);

  const strength = useMemo(() => checkPasswordStrength(password), [password]);
  const passwordsMatch = confirmPassword.length === 0 || confirmPassword === password;

  const canSubmit =
    email.trim().length > 0 &&
    strength.valid &&
    confirmPassword === password &&
    !isSubmitting;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setValidationDetails(undefined);
    setTouchedPassword(true);

    if (!strength.valid) {
      setFormError(strength.message ?? 'Please choose a stronger password.');
      return;
    }
    if (confirmPassword !== password) {
      setFormError('Passwords do not match.');
      return;
    }

    setIsSubmitting(true);
    try {
      await register({
        email: email.trim(),
        password,
        full_name: fullName.trim() || undefined,
      });
    } catch (err) {
      const parsed = parseApiError(err);
      setFormError(parsed.message);
      setValidationDetails(parsed.details);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <AuthLayout>
      {/* Header */}
      <div className="mb-5">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold tracking-wide uppercase bg-brand-soft text-brand border border-brand/20 mb-3 select-none">
          <UserPlus className="w-3 h-3 text-brand" />
          <span>User Registration</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Create your account</h1>
        <p className="text-xs text-slate-500 mt-1">
          Sign up to access MailinteL threat intelligence and email forensic analysis
        </p>
      </div>

      {formError && !validationDetails && (
        <div
          role="alert"
          className="flex items-start gap-2.5 rounded-xl border border-rose-200 bg-rose-50/80 p-3.5 mb-5 text-rose-800"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
          <p className="text-xs font-medium leading-relaxed">{formError}</p>
        </div>
      )}

      {validationDetails && validationDetails.length > 0 && (
        <ValidationErrorBanner message={formError ?? undefined} details={validationDetails} className="mb-5" />
      )}

      <form onSubmit={handleSubmit} className="space-y-3.5">
        {/* Full Name & Email in responsive grid */}
        <div className="space-y-3.5">
          <div>
            <label htmlFor="reg-name" className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
              Full Name <span className="text-slate-400 font-normal lowercase">(optional)</span>
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                id="reg-name"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="w-full pl-10 pr-3.5 py-2.5 text-sm bg-slate-50/70 hover:bg-white border border-slate-200 rounded-xl text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-4 focus:ring-brand/10 focus:border-brand transition-all"
                placeholder="Jane Doe"
              />
            </div>
          </div>

          <div>
            <label htmlFor="reg-email" className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
              Email Address
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                id="reg-email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-10 pr-3.5 py-2.5 text-sm bg-slate-50/70 hover:bg-white border border-slate-200 rounded-xl text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-4 focus:ring-brand/10 focus:border-brand transition-all"
                placeholder="user@domain.com"
              />
            </div>
          </div>
        </div>

        {/* Password */}
        <div>
          <label htmlFor="reg-password" className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
            Password
          </label>
          <div className="relative">
            <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="reg-password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="new-password"
              required
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (!touchedPassword) setTouchedPassword(true);
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

          {/* Strength Bar */}
          {touchedPassword && password.length > 0 && (
            <div className="mt-2 space-y-1">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-500">Security Strength:</span>
                <span className={`font-semibold ${strength.score >= 3 ? 'text-emerald-600' : 'text-amber-600'}`}>
                  {STRENGTH_LABEL[strength.score]}
                </span>
              </div>
              <div className="grid grid-cols-5 gap-1 h-1.5">
                {[0, 1, 2, 3, 4].map((idx) => (
                  <div
                    key={idx}
                    className={`rounded-full transition-all duration-300 ${
                      idx <= strength.score ? STRENGTH_COLOR[strength.score] : 'bg-slate-200'
                    }`}
                  />
                ))}
              </div>
              {strength.message && (
                <p className="text-[11px] text-slate-500 pt-0.5">{strength.message}</p>
              )}
            </div>
          )}
        </div>

        {/* Confirm Password */}
        <div>
          <label htmlFor="reg-confirm" className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
            Confirm Password
          </label>
          <div className="relative">
            <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="reg-confirm"
              type={showPassword ? 'text' : 'password'}
              autoComplete="new-password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className={`w-full pl-10 pr-10 py-2.5 text-sm bg-slate-50/70 hover:bg-white border rounded-xl text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-4 focus:ring-brand/10 transition-all font-mono tracking-wide placeholder:font-sans placeholder:tracking-normal ${
                passwordsMatch ? 'border-slate-200 focus:border-brand' : 'border-rose-300 focus:border-rose-400'
              }`}
              placeholder="••••••••••••"
            />
            {confirmPassword.length > 0 && passwordsMatch && (
              <Check className="w-4 h-4 text-emerald-500 absolute right-3.5 top-1/2 -translate-y-1/2" />
            )}
          </div>
          {!passwordsMatch && (
            <p className="text-[11px] text-rose-600 mt-1 font-medium">Passwords do not match.</p>
          )}
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full mt-2 flex items-center justify-center gap-2 bg-gradient-to-r from-brand to-[#1D4E9E] hover:from-[#1D4E9E] hover:to-[#163E80] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold py-2.5 px-4 rounded-xl shadow-sm hover:shadow-md hover:shadow-brand/20 active:scale-[0.99] transition-all"
        >
          {isSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
          {isSubmitting ? 'Creating account…' : 'Create account'}
        </button>
      </form>

      {/* Switch to Login */}
      <div className="mt-5 pt-4 border-t border-slate-100 text-center">
        <p className="text-xs text-slate-500">
          Already have an account?{' '}
          <button
            type="button"
            onClick={onSwitchToLogin}
            className="font-semibold text-brand hover:text-brand-hover hover:underline transition-colors"
          >
            Sign in
          </button>
        </p>
      </div>
    </AuthLayout>
  );
};

export default RegisterScreen;
