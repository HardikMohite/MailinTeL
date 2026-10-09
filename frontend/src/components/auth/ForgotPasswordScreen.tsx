import React, { useState } from 'react';
import { Mail, ArrowLeft, Loader2, CheckCircle2, AlertTriangle, ShieldAlert, KeyRound } from 'lucide-react';
import { AuthLayout } from './AuthLayout';

interface ForgotPasswordScreenProps {
  onSwitchToLogin: () => void;
}

export const ForgotPasswordScreen: React.FC<ForgotPasswordScreenProps> = ({ onSwitchToLogin }) => {
  const [email, setEmail] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting || !email.trim()) return;

    setErrorMessage(null);
    setIsSubmitting(true);

    try {
      // Simulate/Trigger password recovery dispatch
      // In enterprise threat intelligence suites, this dispatches security notice without user-enumeration
      await new Promise((resolve) => setTimeout(resolve, 800));
      setIsSubmitted(true);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'An error occurred while requesting password reset.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <AuthLayout>
      {/* Back button */}
      <button
        type="button"
        onClick={onSwitchToLogin}
        className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-brand transition-colors mb-5 group"
      >
        <ArrowLeft className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
        <span>Back to sign in</span>
      </button>

      {!isSubmitted ? (
        <>
          {/* Header */}
          <div className="flex items-center gap-3.5 mb-6">
            <div className="w-11 h-11 rounded-xl bg-brand-soft border border-brand/20 flex items-center justify-center shrink-0">
              <KeyRound className="w-5 h-5 text-brand" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">Reset password</h1>
              <p className="text-xs text-slate-500 mt-0.5">
                Recover access to your MailinteL forensic workspace
              </p>
            </div>
          </div>

          <p className="text-xs text-slate-600 mb-5 leading-relaxed">
            Enter your work email address below. If an active account matches, we will dispatch secure password reset instructions.
          </p>

          {errorMessage && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-xl border border-rose-200 bg-rose-50/80 p-3.5 mb-5 text-rose-800"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
              <p className="text-xs font-medium">{errorMessage}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="reset-email" className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
                Work Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="reset-email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-3.5 py-2.5 text-sm bg-slate-50/70 hover:bg-white border border-slate-200 rounded-xl text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-4 focus:ring-brand/10 focus:border-brand transition-all"
                  placeholder="analyst@organization.com"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting || !email.trim()}
              className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-60 disabled:cursor-not-allowed text-white text-sm font-semibold py-3 px-4 rounded-xl shadow-md shadow-blue-500/25 active:scale-[0.99] transition-all cursor-pointer"
            >
              {isSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
              {isSubmitting ? 'Sending instructions…' : 'Send reset instructions'}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-slate-100 flex items-start gap-2.5 bg-slate-50/80 rounded-xl p-3 text-[11px] text-slate-500">
            <ShieldAlert className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
            <span>
              For organization-managed accounts, your primary Institution Administrator or System Admin can also reset your credentials.
            </span>
          </div>
        </>
      ) : (
        /* Submitted Success State */
        <div className="text-center py-2">
          <div className="w-14 h-14 rounded-2xl bg-emerald-50 border border-emerald-200 flex items-center justify-center mx-auto mb-4 text-emerald-600 shadow-sm">
            <CheckCircle2 className="w-7 h-7" />
          </div>

          <h2 className="text-lg font-bold text-slate-900 mb-1.5">Check your inbox</h2>
          <p className="text-xs text-slate-600 mb-5 leading-relaxed">
            If an account exists for <span className="font-semibold text-slate-900">{email}</span>, password reset instructions have been dispatched.
          </p>

          <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-3.5 mb-6 text-left">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 mb-1">
              <Mail className="w-3.5 h-3.5 text-blue-600" />
              <span>Security Reminder</span>
            </div>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Reset links expire in 15 minutes. If you do not see the email, please check your spam folder or verify with your system administrator.
            </p>
          </div>

          <div className="space-y-2">
            <button
              type="button"
              onClick={onSwitchToLogin}
              className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-sm font-semibold py-3 px-4 rounded-xl shadow-md shadow-blue-500/25 transition-all cursor-pointer"
            >
              Return to sign in
            </button>

            <button
              type="button"
              onClick={() => {
                setIsSubmitted(false);
                setEmail('');
              }}
              className="text-xs font-medium text-slate-500 hover:text-slate-800 transition-colors py-1"
            >
              Try another email address
            </button>
          </div>
        </div>
      )}
    </AuthLayout>
  );
};

export default ForgotPasswordScreen;
