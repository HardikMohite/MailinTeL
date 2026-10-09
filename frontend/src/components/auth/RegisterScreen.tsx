import React, { useMemo, useState } from 'react';
import {
  Mail,
  Lock,
  Eye,
  EyeOff,
  User,
  AtSign,
  AlertTriangle,
  Loader2,
  Check,
  ArrowRight,
} from 'lucide-react';
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
  'bg-blue-500',
  'bg-emerald-500',
];

export const RegisterScreen: React.FC<RegisterScreenProps> = ({ onSwitchToLogin }) => {
  const { register } = useAuth();
  const parseApiError = useApiErrorHandler();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [agreedToTerms, setAgreedToTerms] = useState(true);

  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [touchedPassword, setTouchedPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [validationDetails, setValidationDetails] = useState<PydanticErrorDetail[] | undefined>(undefined);

  const strength = useMemo(() => checkPasswordStrength(password), [password]);
  const passwordsMatch = confirmPassword.length === 0 || confirmPassword === password;

  const canSubmit =
    fullName.trim().length > 0 &&
    email.trim().length > 0 &&
    username.trim().length >= 3 &&
    strength.valid &&
    confirmPassword === password &&
    agreedToTerms &&
    !isSubmitting;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setValidationDetails(undefined);
    setTouchedPassword(true);

    if (!fullName.trim()) {
      setFormError('Full Name is required.');
      return;
    }
    if (!email.trim()) {
      setFormError('Email is required.');
      return;
    }
    if (!username.trim()) {
      setFormError('Username is required.');
      return;
    }
    if (username.trim().length < 3) {
      setFormError('Username must be at least 3 characters long.');
      return;
    }
    if (!strength.valid) {
      setFormError(strength.message ?? 'Please choose a stronger password.');
      return;
    }
    if (confirmPassword !== password) {
      setFormError('Passwords do not match.');
      return;
    }
    if (!agreedToTerms) {
      setFormError('You must agree to the platform security terms to proceed.');
      return;
    }

    setIsSubmitting(true);
    try {
      await register({
        full_name: fullName.trim(),
        email: email.trim(),
        username: username.trim(),
        password,
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
    <AuthLayout
      heroHeadline={
        <>
          <span className="block text-slate-950 font-black">Deconstruct Threats.</span>
          <span className="block text-blue-600 font-black mt-3 sm:mt-3.5">Unmask Origin Footprints.</span>
        </>
      }
      heroSubtitle="Equip your cyber cell investigators, forensic examiners, and SOC analysts with deep header parsing, DNA isolation, and multi-tenant campaign correlation."
      features={[
        'Passive Origin & Geo-Forwarding Footprint Triangulation',
        '5-Strand Composite Email DNA Fingerprinting',
        'Cross-Tenant Campaign Correlation & Graph Intelligence',
        'ISO/IEC 27037 Tamper-Proof Cryptographic Chain of Custody',
      ]}
    >
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">Create Forensic Account</h1>
        <p className="text-sm text-slate-500 mt-1.5">
          Join MailinTeL to investigate email threats and adversary campaigns.
        </p>
      </div>

      {formError && !validationDetails && (
        <div
          role="alert"
          className="flex flex-col gap-2 rounded-xl border border-rose-200 bg-rose-50/90 p-3.5 mb-5 text-rose-800"
        >
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
            <div className="flex-1">
              <p className="text-xs font-medium leading-relaxed">{formError}</p>
              {(formError.toLowerCase().includes('already exist') || formError.toLowerCase().includes('unable to register')) && (
                <button
                  type="button"
                  onClick={onSwitchToLogin}
                  className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold text-blue-600 hover:text-blue-700 hover:underline cursor-pointer"
                >
                  Already registered? Sign in with this account &rarr;
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {validationDetails && validationDetails.length > 0 && (
        <ValidationErrorBanner message={formError ?? undefined} details={validationDetails} className="mb-5" />
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* 1. Full Name */}
        <div>
          <label htmlFor="reg-name" className="block text-xs font-bold text-slate-700 tracking-wider mb-1.5">
            Full Name
          </label>
          <div className="relative">
            <User className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="reg-name"
              type="text"
              autoComplete="name"
              required
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full pl-10 pr-3.5 py-2.5 text-sm bg-white hover:border-slate-400 focus:bg-white border border-slate-300 rounded-xl text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-600 transition-all shadow-2xs"
              placeholder="Hardik Mohite"
            />
          </div>
        </div>

        {/* 2. Email */}
        <div>
          <label htmlFor="reg-email" className="block text-xs font-bold text-slate-700 tracking-wider mb-1.5">
            Email
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
              className="w-full pl-10 pr-3.5 py-2.5 text-sm bg-white hover:border-slate-400 focus:bg-white border border-slate-300 rounded-xl text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-600 transition-all shadow-2xs"
              placeholder="hardik@mailintel.io"
            />
          </div>
        </div>

        {/* 3. Username */}
        <div>
          <label htmlFor="reg-username" className="block text-xs font-bold text-slate-700 tracking-wider mb-1.5">
            Username
          </label>
          <div className="relative">
            <AtSign className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="reg-username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_.-]/g, ''))}
              className="w-full pl-10 pr-3.5 py-2.5 text-sm bg-white hover:border-slate-400 focus:bg-white border border-slate-300 rounded-xl text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-600 transition-all font-mono shadow-2xs"
              placeholder="hardik_mohite"
            />
          </div>
        </div>

        {/* 4. Password */}
        <div>
          <label htmlFor="reg-password" className="block text-xs font-bold text-slate-700 tracking-wider mb-1.5">
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
              className="w-full pl-10 pr-10 py-2.5 text-sm bg-white hover:border-slate-400 focus:bg-white border border-slate-300 rounded-xl text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-600 transition-all font-mono tracking-wide placeholder:font-sans placeholder:tracking-normal shadow-2xs"
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

          {/* Dynamic Password Strength Progress Meter */}
          {touchedPassword && password.length > 0 && (
            <div className="mt-2 space-y-1.5 p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-600 font-medium">Security Strength:</span>
                <span className={`font-bold ${strength.score >= 3 ? 'text-emerald-600' : 'text-amber-600'}`}>
                  {STRENGTH_LABEL[strength.score]}
                </span>
              </div>
              <div className="grid grid-cols-5 gap-1.5 h-1.5">
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
                <p className="text-[11px] text-slate-600 pt-0.5">{strength.message}</p>
              )}
            </div>
          )}
        </div>

        {/* 5. Confirm Password */}
        <div>
          <label htmlFor="reg-confirm" className="block text-xs font-bold text-slate-700 tracking-wider mb-1.5">
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
              className={`w-full pl-10 pr-10 py-2.5 text-sm bg-white hover:border-slate-400 focus:bg-white border rounded-xl text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-4 focus:ring-blue-500/10 transition-all font-mono tracking-wide placeholder:font-sans placeholder:tracking-normal shadow-2xs ${
                passwordsMatch ? 'border-slate-300 focus:border-blue-600' : 'border-rose-400 focus:border-rose-500'
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

        {/* Platform Compliance & Terms Checkbox */}
        <div className="pt-1">
          <label className="flex items-start gap-2.5 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={agreedToTerms}
              onChange={(e) => setAgreedToTerms(e.target.checked)}
              className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500/25 cursor-pointer"
            />
            <span className="text-xs text-slate-600 leading-relaxed font-normal">
              I agree to the <span className="text-blue-600 font-semibold hover:underline">Forensic Code of Conduct</span> and <span className="text-blue-600 font-semibold hover:underline">Platform Privacy Policy</span>.
            </span>
          </label>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full mt-2 flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold py-3 px-4 rounded-xl shadow-md shadow-blue-500/25 active:scale-[0.99] transition-all cursor-pointer"
        >
          {isSubmitting ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <>
              <span>Create Account</span>
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </form>

      {/* Switch to Login */}
      <div className="mt-6 pt-5 border-t border-slate-100 text-center">
        <p className="text-xs text-slate-500">
          Already have an account?{' '}
          <button
            type="button"
            onClick={onSwitchToLogin}
            className="font-semibold text-blue-600 hover:text-blue-700 hover:underline transition-colors cursor-pointer"
          >
            Sign in
          </button>
        </p>
      </div>
    </AuthLayout>
  );
};

export default RegisterScreen;
