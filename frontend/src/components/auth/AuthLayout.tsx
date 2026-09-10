import React from 'react';
import { BrandLogo } from '../common/BrandLogo';

interface AuthLayoutProps {
  children: React.ReactNode;
}

export const AuthLayout: React.FC<AuthLayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-[#F8FAFC] flex flex-col justify-between relative overflow-hidden selection:bg-brand-soft selection:text-brand">
      {/* Ambient background decoration */}
      <div 
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: `
            radial-gradient(ellipse 80% 50% at 50% -20%, rgba(37, 99, 184, 0.09), transparent 70%),
            radial-gradient(circle at 100% 100%, rgba(37, 99, 184, 0.04), transparent 40%),
            radial-gradient(circle at 0% 100%, rgba(37, 99, 184, 0.04), transparent 40%)
          `,
        }}
      />

      {/* Subtle enterprise tech grid */}
      <div 
        className="absolute inset-0 pointer-events-none opacity-[0.035]"
        style={{
          backgroundImage: `linear-gradient(#101C33 1px, transparent 1px), linear-gradient(to right, #101C33 1px, transparent 1px)`,
          backgroundSize: '32px 32px',
        }}
      />

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col items-center justify-center px-4 sm:px-6 py-6 sm:py-10 relative z-10">
        <div className="w-full max-w-[460px] mx-auto flex flex-col items-center">
          {/* Logo Section */}
          <div className="mb-5 sm:mb-6 transition-all duration-300">
            <BrandLogo variant="hero" surface="light" />
          </div>

          {/* Form Card Container */}
          <div className="w-full bg-white border border-slate-200/90 rounded-2xl shadow-xl shadow-slate-200/50 p-7 sm:p-9 relative overflow-hidden backdrop-blur-sm">
            {/* Top accent line */}
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-brand via-brand to-[#1D4E9E]" />
            {children}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 pb-8 px-4 text-center">
        <p className="text-xs text-slate-400">
          &copy; {new Date().getFullYear()} MailinteL. All rights reserved.
        </p>
      </footer>
    </div>
  );
};

export default AuthLayout;
