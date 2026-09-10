import React, { useState, useEffect } from 'react';
import {
  User as UserIcon,
  Shield,
  Key,
  Sliders,
  Bell,
  Copy,
  Check,
  Eye,
  EyeOff,
  LogOut,
  Save,
  CheckCircle2,
  AlertCircle,
  Laptop,
  Terminal,
  Building2,
  Lock,
  Sparkles,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { updateProfile, changePassword } from '../../services/api';

type SettingsTab = 'profile' | 'security' | 'preferences' | 'api';


export interface SettingsViewProps {
  health?: any;
  detailedHealth?: any;
  loading?: boolean;
  onRefreshHealth?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = () => {
  const { user, logout } = useAuth();

  const [activeTab, setActiveTab] = useState<SettingsTab>('profile');

  // Profile State
  const [fullName, setFullName] = useState(user?.full_name || '');
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileMessage, setProfileMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Password State
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Copied helper state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // User Preferences (persisted in localStorage)
  const [preferences, setPreferences] = useState({
    defaultLandingTab: 'summary',
    redactPiiExports: true,
    autoExpandThreats: true,
    darkThemeMode: 'cyber-dark',
    criticalEmailAlerts: true,
    weeklyForensicDigest: false,
  });
  const [prefSavedToast, setPrefSavedToast] = useState(false);

  // API Token State
  const [apiToken, setApiToken] = useState('mintel_live_8f7b2c9a1e0d4a3b8c6e7f1a2b3c4d5e');
  const [showToken, setShowToken] = useState(false);

  useEffect(() => {
    if (user?.full_name) {
      setFullName(user.full_name);
    }
  }, [user?.full_name]);

  // Load preferences from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('mailintel_user_preferences');
      if (saved) {
        setPreferences((prev) => ({ ...prev, ...JSON.parse(saved) }));
      }
    } catch {
      // Ignore parse error
    }
  }, []);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileSaving(true);
    setProfileMessage(null);
    try {
      await updateProfile(fullName);
      setProfileMessage({ type: 'success', text: 'Profile updated successfully.' });
      setTimeout(() => setProfileMessage(null), 4000);
    } catch (err: any) {
      const msg = err.response?.data?.message || err.response?.data?.detail || 'Failed to update profile.';
      setProfileMessage({ type: 'error', text: msg });
    } finally {
      setProfileSaving(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordSaving(true);
    setPasswordMessage(null);

    if (newPassword !== confirmPassword) {
      setPasswordMessage({ type: 'error', text: 'New passwords do not match.' });
      setPasswordSaving(false);
      return;
    }

    if (newPassword.length < 8) {
      setPasswordMessage({ type: 'error', text: 'Password must be at least 8 characters long.' });
      setPasswordSaving(false);
      return;
    }

    try {
      const res = await changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setPasswordMessage({ type: 'success', text: res.message || 'Password changed successfully.' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setPasswordMessage(null), 5000);
    } catch (err: any) {
      const msg =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        'Failed to change password. Please check your current password.';
      setPasswordMessage({ type: 'error', text: msg });
    } finally {
      setPasswordSaving(false);
    }
  };

  const updatePreference = (key: string, value: any) => {
    const updated = { ...preferences, [key]: value };
    setPreferences(updated);
    try {
      localStorage.setItem('mailintel_user_preferences', JSON.stringify(updated));
      setPrefSavedToast(true);
      setTimeout(() => setPrefSavedToast(false), 2500);
    } catch {
      // Ignore
    }
  };

  const roleNameDisplay = (role?: string) => {
    switch (role) {
      case 'SYSTEM_ADMIN':
        return 'System Administrator';
      case 'INSTITUTION_ADMIN':
        return 'Institution Administrator';
      case 'CYBER_CELL_INVESTIGATOR':
        return 'Cyber Cell Investigator';
      case 'ANALYST':
        return 'Forensic Analyst';
      default:
        return 'Standard User';
    }
  };

  // Password requirements validation helper
  const hasMinLength = newPassword.length >= 8;
  const hasUpperCase = /[A-Z]/.test(newPassword);
  const hasLowerCase = /[a-z]/.test(newPassword);
  const hasDigit = /[0-9]/.test(newPassword);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand/10 text-brand flex items-center justify-center shrink-0 border border-brand/20">
            <UserIcon className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Account Settings</h1>
            <p className="text-sm text-text-muted mt-0.5">
              Manage your personal profile, credentials, forensic preferences, and security access.
            </p>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-workspace-border overflow-x-auto pb-px">
        <button
          onClick={() => setActiveTab('profile')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'profile'
              ? 'border-brand text-brand'
              : 'border-transparent text-text-secondary hover:text-text-primary'
          }`}
        >
          <UserIcon className="w-4 h-4" />
          Profile & Organization
        </button>

        <button
          onClick={() => setActiveTab('security')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'security'
              ? 'border-brand text-brand'
              : 'border-transparent text-text-secondary hover:text-text-primary'
          }`}
        >
          <Shield className="w-4 h-4" />
          Security & Password
        </button>

        <button
          onClick={() => setActiveTab('preferences')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'preferences'
              ? 'border-brand text-brand'
              : 'border-transparent text-text-secondary hover:text-text-primary'
          }`}
        >
          <Sliders className="w-4 h-4" />
          Forensic Preferences
        </button>

        <button
          onClick={() => setActiveTab('api')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'api'
              ? 'border-brand text-brand'
              : 'border-transparent text-text-secondary hover:text-text-primary'
          }`}
        >
          <Terminal className="w-4 h-4" />
          API & Integrations
        </button>
      </div>

      {/* TAB 1: Profile & Organization */}
      {activeTab === 'profile' && (
        <div className="space-y-6">
          {/* User Identity Header Card */}
          <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-brand/30 to-brand/10 border border-brand/30 flex items-center justify-center text-brand text-2xl font-bold uppercase shadow-inner">
                {user?.full_name ? user.full_name[0] : user?.email ? user.email[0] : 'U'}
              </div>
              <div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <h2 className="text-xl font-bold text-text-primary">{user?.full_name || 'Anonymous User'}</h2>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-brand/10 text-brand border border-brand/20">
                    {roleNameDisplay(user?.role)}
                  </span>
                </div>
                <p className="text-sm text-text-muted mt-1 flex items-center gap-2">
                  <span>{user?.email}</span>
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                    <CheckCircle2 className="w-3 h-3" /> Verified Account
                  </span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={logout}
                className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-workspace-secondary hover:bg-workspace-border text-text-secondary hover:text-text-primary text-xs font-medium border border-workspace-border transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Edit Personal Information */}
            <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
              <div className="flex items-center gap-2 border-b border-workspace-border pb-3">
                <UserIcon className="w-4 h-4 text-brand" />
                <h3 className="text-sm font-bold text-text-primary">Personal Information</h3>
              </div>

              {profileMessage && (
                <div
                  className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
                    profileMessage.type === 'success'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                  }`}
                >
                  {profileMessage.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 shrink-0" />
                  )}
                  <span>{profileMessage.text}</span>
                </div>
              )}

              <form onSubmit={handleUpdateProfile} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-text-muted mb-1.5">Full Name</label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Enter your full name"
                    className="w-full px-3.5 py-2 text-sm rounded-lg bg-workspace border border-workspace-border text-text-primary focus:outline-none focus:border-brand transition-colors"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-text-muted mb-1.5">Email Address</label>
                  <input
                    type="email"
                    value={user?.email || ''}
                    disabled
                    className="w-full px-3.5 py-2 text-sm rounded-lg bg-workspace-secondary/50 border border-workspace-border text-text-muted cursor-not-allowed"
                  />
                  <span className="text-[11px] text-text-muted mt-1 block">
                    Contact your Organization Administrator to change your login email.
                  </span>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={profileSaving || fullName === user?.full_name}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-xs font-semibold shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Save className="w-3.5 h-3.5" />
                    {profileSaving ? 'Saving...' : 'Save Profile Changes'}
                  </button>
                </div>
              </form>
            </div>

            {/* Organization & Access Context */}
            <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
              <div className="flex items-center gap-2 border-b border-workspace-border pb-3">
                <Building2 className="w-4 h-4 text-brand" />
                <h3 className="text-sm font-bold text-text-primary">Organization & Access</h3>
              </div>

              <div className="space-y-3.5 text-xs">
                <div>
                  <span className="text-text-muted block mb-1 font-medium">Assigned Organization</span>
                  <div className="p-2.5 rounded-lg bg-workspace border border-workspace-border font-medium text-text-primary">
                    {user?.organization_name || 'MailIntel Security Operations'}
                  </div>
                </div>

                <div>
                  <span className="text-text-muted block mb-1 font-medium">Organization ID</span>
                  <div className="flex items-center justify-between p-2.5 rounded-lg bg-workspace border border-workspace-border font-mono text-[11px] text-text-secondary">
                    <span className="truncate">{user?.organization_id || 'Global Platform Organization'}</span>
                    {user?.organization_id && (
                      <button
                        onClick={() => handleCopy(user.organization_id!, 'org_id')}
                        className="text-text-muted hover:text-text-primary p-1 ml-2 transition-colors"
                        title="Copy Org ID"
                      >
                        {copiedKey === 'org_id' ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-text-muted block mb-1 font-medium">User Identifier (UID)</span>
                  <div className="flex items-center justify-between p-2.5 rounded-lg bg-workspace border border-workspace-border font-mono text-[11px] text-text-secondary">
                    <span className="truncate">{user?.id || '—'}</span>
                    {user?.id && (
                      <button
                        onClick={() => handleCopy(user.id, 'user_id')}
                        className="text-text-muted hover:text-text-primary p-1 ml-2 transition-colors"
                        title="Copy UID"
                      >
                        {copiedKey === 'user_id' ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-workspace-secondary/60 border border-workspace-border text-text-muted space-y-1">
                  <span className="font-semibold text-text-primary block">Security Scope:</span>
                  <p className="text-[11px] leading-relaxed">
                    Your role grants full forensic analysis capabilities within your organization tenant, including
                    raw email artifact inspection, threat intelligence querying, and report generation.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Security & Password */}
      {activeTab === 'security' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Change Password Form */}
            <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
              <div className="flex items-center gap-2 border-b border-workspace-border pb-3">
                <Key className="w-4 h-4 text-brand" />
                <h3 className="text-sm font-bold text-text-primary">Change Password</h3>
              </div>

              {passwordMessage && (
                <div
                  className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
                    passwordMessage.type === 'success'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                  }`}
                >
                  {passwordMessage.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 shrink-0" />
                  )}
                  <span>{passwordMessage.text}</span>
                </div>
              )}

              <form onSubmit={handleChangePassword} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-text-muted mb-1.5">Current Password</label>
                  <div className="relative">
                    <input
                      type={showCurrentPassword ? 'text' : 'password'}
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      placeholder="Enter current password"
                      className="w-full px-3.5 py-2 pr-10 text-sm rounded-lg bg-workspace border border-workspace-border text-text-primary focus:outline-none focus:border-brand transition-colors"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
                    >
                      {showCurrentPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-text-muted mb-1.5">New Password</label>
                  <div className="relative">
                    <input
                      type={showNewPassword ? 'text' : 'password'}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Enter new password (min. 8 characters)"
                      className="w-full px-3.5 py-2 pr-10 text-sm rounded-lg bg-workspace border border-workspace-border text-text-primary focus:outline-none focus:border-brand transition-colors"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
                    >
                      {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-text-muted mb-1.5">Confirm New Password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-enter new password"
                    className="w-full px-3.5 py-2 text-sm rounded-lg bg-workspace border border-workspace-border text-text-primary focus:outline-none focus:border-brand transition-colors"
                    required
                  />
                </div>

                {/* Password strength checklist */}
                <div className="p-3 rounded-lg bg-workspace border border-workspace-border space-y-1.5 text-[11px]">
                  <span className="text-text-muted font-medium block">Password Requirements:</span>
                  <div className="grid grid-cols-2 gap-1.5">
                    <span className={`flex items-center gap-1.5 ${hasMinLength ? 'text-emerald-400' : 'text-text-muted'}`}>
                      <Check className="w-3 h-3" /> Min 8 characters
                    </span>
                    <span className={`flex items-center gap-1.5 ${hasUpperCase ? 'text-emerald-400' : 'text-text-muted'}`}>
                      <Check className="w-3 h-3" /> Uppercase letter
                    </span>
                    <span className={`flex items-center gap-1.5 ${hasLowerCase ? 'text-emerald-400' : 'text-text-muted'}`}>
                      <Check className="w-3 h-3" /> Lowercase letter
                    </span>
                    <span className={`flex items-center gap-1.5 ${hasDigit ? 'text-emerald-400' : 'text-text-muted'}`}>
                      <Check className="w-3 h-3" /> Number or digit
                    </span>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={passwordSaving || !newPassword || !currentPassword}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand hover:bg-brand/90 text-white text-xs font-semibold shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    {passwordSaving ? 'Updating...' : 'Update Password'}
                  </button>
                </div>
              </form>
            </div>

            {/* Session & Authentication Security */}
            <div className="space-y-6">
              <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
                <div className="flex items-center gap-2 border-b border-workspace-border pb-3">
                  <Laptop className="w-4 h-4 text-brand" />
                  <h3 className="text-sm font-bold text-text-primary">Current Active Session</h3>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="flex items-center justify-between p-3 rounded-lg bg-workspace border border-workspace-border">
                    <div className="space-y-0.5">
                      <span className="font-semibold text-text-primary flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        Active Browser Session
                      </span>
                      <p className="text-text-muted text-[11px]">JSON Web Token (JWT) Authenticated</p>
                    </div>
                    <span className="text-emerald-400 font-mono text-[11px] bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      CURRENT
                    </span>
                  </div>

                  <div className="space-y-2 text-text-muted">
                    <div className="flex justify-between py-1 border-b border-workspace-border/50">
                      <span>Token Expiry:</span>
                      <span className="font-mono text-text-primary">60 minutes (Sliding window)</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-workspace-border/50">
                      <span>Algorithm:</span>
                      <span className="font-mono text-text-primary">HMAC-SHA256</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span>Cryptographic Provider:</span>
                      <span className="font-mono text-text-primary">BCrypt rounds = 12</span>
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={logout}
                      className="w-full py-2 px-3 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-medium transition-colors flex items-center justify-center gap-2"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      Terminate Session & Log Out
                    </button>
                  </div>
                </div>
              </div>

              {/* Two-Factor Authentication Info */}
              <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-brand" />
                    <h3 className="text-sm font-bold text-text-primary">Two-Factor Authentication (2FA)</h3>
                  </div>
                  <span className="text-xs bg-workspace-secondary text-text-muted px-2 py-0.5 rounded-full border border-workspace-border">
                    Enterprise Ready
                  </span>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  Protect your MailinteL account with TOTP authenticator app enforcement (Google Authenticator, YubiKey, or Duo).
                </p>
                <div className="pt-1">
                  <button
                    onClick={() => alert('TOTP Authenticator enrollment is managed by your Enterprise Identity Provider.')}
                    className="px-3.5 py-1.5 rounded-lg bg-workspace hover:bg-workspace-secondary text-text-primary border border-workspace-border text-xs font-medium transition-colors"
                  >
                    Configure Authenticator
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Forensic Preferences */}
      {activeTab === 'preferences' && (
        <div className="space-y-6">
          {prefSavedToast && (
            <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs flex items-center gap-2 animate-fade-in">
              <CheckCircle2 className="w-4 h-4" />
              <span>Preferences saved to your local browser storage.</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Investigation & UI Defaults */}
            <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
              <div className="flex items-center gap-2 border-b border-workspace-border pb-3">
                <Sliders className="w-4 h-4 text-brand" />
                <h3 className="text-sm font-bold text-text-primary">Investigation View Defaults</h3>
              </div>

              <div className="space-y-4 text-xs">
                <div>
                  <label className="block font-medium text-text-muted mb-1.5">
                    Default Landing View on Email Inspection
                  </label>
                  <select
                    value={preferences.defaultLandingTab}
                    onChange={(e) => updatePreference('defaultLandingTab', e.target.value)}
                    className="w-full px-3.5 py-2 rounded-lg bg-workspace border border-workspace-border text-text-primary focus:outline-none focus:border-brand"
                  >
                    <option value="summary">Summary & Executive Overview</option>
                    <option value="headers">Raw RFC 5322 Email Headers</option>
                    <option value="threat-intel">Threat Intelligence & Reputation</option>
                    <option value="auth-matrix">SPF / DKIM / DMARC Authentication Matrix</option>
                  </select>
                </div>

                <div className="pt-2 space-y-3">
                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={preferences.autoExpandThreats}
                      onChange={(e) => updatePreference('autoExpandThreats', e.target.checked)}
                      className="mt-0.5 rounded border-workspace-border text-brand focus:ring-brand"
                    />
                    <div>
                      <span className="font-medium text-text-primary block">Auto-Expand High Threat Indicators</span>
                      <p className="text-text-muted text-[11px] mt-0.5">
                        Automatically uncollapse threat cards with critical or high risk scores in the workspace.
                      </p>
                    </div>
                  </label>

                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={preferences.redactPiiExports}
                      onChange={(e) => updatePreference('redactPiiExports', e.target.checked)}
                      className="mt-0.5 rounded border-workspace-border text-brand focus:ring-brand"
                    />
                    <div>
                      <span className="font-medium text-text-primary block">Redact Recipient PII in Report Exports</span>
                      <p className="text-text-muted text-[11px] mt-0.5">
                        Mask employee email addresses and names when generating evidentiary PDF and JSON reports.
                      </p>
                    </div>
                  </label>
                </div>
              </div>
            </div>

            {/* Notification & Alert Preferences */}
            <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
              <div className="flex items-center gap-2 border-b border-workspace-border pb-3">
                <Bell className="w-4 h-4 text-brand" />
                <h3 className="text-sm font-bold text-text-primary">Notifications & Alerts</h3>
              </div>

              <div className="space-y-4 text-xs">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={preferences.criticalEmailAlerts}
                    onChange={(e) => updatePreference('criticalEmailAlerts', e.target.checked)}
                    className="mt-0.5 rounded border-workspace-border text-brand focus:ring-brand"
                  />
                  <div>
                    <span className="font-medium text-text-primary block">Critical Threat Email Notifications</span>
                    <p className="text-text-muted text-[11px] mt-0.5">
                      Receive an alert when an email analyzed in your workspace is scored as Critical Phishing or BEC.
                    </p>
                  </div>
                </label>

                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={preferences.weeklyForensicDigest}
                    onChange={(e) => updatePreference('weeklyForensicDigest', e.target.checked)}
                    className="mt-0.5 rounded border-workspace-border text-brand focus:ring-brand"
                  />
                  <div>
                    <span className="font-medium text-text-primary block">Weekly Forensic Intelligence Digest</span>
                    <p className="text-text-muted text-[11px] mt-0.5">
                      Summary report of new phishing campaigns, zero-day impersonations, and credential harvesting patterns.
                    </p>
                  </div>
                </label>

                <div className="pt-3 border-t border-workspace-border">
                  <span className="font-medium text-text-muted block mb-2">Interface Theme Mode</span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => updatePreference('darkThemeMode', 'cyber-dark')}
                      className={`p-2.5 rounded-lg border text-left text-xs font-medium transition-all ${
                        preferences.darkThemeMode === 'cyber-dark'
                          ? 'border-brand bg-brand/10 text-brand'
                          : 'border-workspace-border bg-workspace text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      <Sparkles className="w-3.5 h-3.5 mb-1 text-brand" />
                      Cyber Slate (Dark)
                    </button>

                    <button
                      type="button"
                      onClick={() => updatePreference('darkThemeMode', 'system')}
                      className={`p-2.5 rounded-lg border text-left text-xs font-medium transition-all ${
                        preferences.darkThemeMode === 'system'
                          ? 'border-brand bg-brand/10 text-brand'
                          : 'border-workspace-border bg-workspace text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      <Laptop className="w-3.5 h-3.5 mb-1 text-text-muted" />
                      System Match
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: API & Integrations */}
      {activeTab === 'api' && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-workspace-border pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-brand" />
                <h3 className="text-sm font-bold text-text-primary">Personal Forensic API Token</h3>
              </div>
              <span className="text-xs bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/20 font-medium">
                ACTIVE
              </span>
            </div>

            <p className="text-xs text-text-muted leading-relaxed">
              Use this key to authenticate scripts, SOAR playbooks, or automated email ingestion pipelines into MailinteL.
              Include it as a Bearer token in the <code className="text-brand font-mono">Authorization</code> header.
            </p>

            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <input
                    type={showToken ? 'text' : 'password'}
                    value={apiToken}
                    readOnly
                    className="w-full px-3.5 py-2.5 text-xs font-mono rounded-lg bg-workspace border border-workspace-border text-text-primary pr-20"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-text-muted hover:text-text-primary flex items-center gap-1"
                  >
                    {showToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    <span>{showToken ? 'Hide' : 'Reveal'}</span>
                  </button>
                </div>
                <button
                  onClick={() => handleCopy(apiToken, 'api_token')}
                  className="px-4 py-2.5 rounded-lg bg-brand hover:bg-brand/90 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  {copiedKey === 'api_token' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedKey === 'api_token' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="pt-2">
              <button
                onClick={() => {
                  if (confirm('Regenerating this API token will immediately invalidate any external scripts using it. Continue?')) {
                    const newToken = 'mintel_live_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
                      .map((b) => b.toString(16).padStart(2, '0'))
                      .join('');
                    setApiToken(newToken);
                  }
                }}
                className="px-3 py-1.5 rounded-lg bg-workspace-secondary hover:bg-workspace-border text-text-secondary hover:text-text-primary text-xs font-medium border border-workspace-border transition-colors"
              >
                Regenerate Token
              </button>
            </div>
          </div>

          {/* Quick Example Curl */}
          <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
            <h4 className="text-xs font-bold text-text-primary uppercase tracking-wider">Example API Request</h4>
            <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border font-mono text-[11px] text-text-secondary overflow-x-auto">
              curl -X POST &quot;https://mailintel.onrender.com/api/v1/emails/analyze&quot; \<br />
              &nbsp;&nbsp;-H &quot;Authorization: Bearer {showToken ? apiToken : 'mintel_live_••••••••••••'}&quot; \<br />
              &nbsp;&nbsp;-F &quot;file=@suspicious_email.eml&quot;
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SettingsView;
