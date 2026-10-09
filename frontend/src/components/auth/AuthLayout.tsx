import React from 'react';
import { Check, ShieldCheck } from 'lucide-react';

interface AuthLayoutProps {
  children: React.ReactNode;
  heroHeadline?: React.ReactNode;
  heroSubtitle?: string;
  features?: string[];
}

const DEFAULT_MAILINTEL_FEATURES = [
  'Passive Origin & Geo-Forwarding Footprint Triangulation',
  '5-Strand Composite Email DNA Fingerprinting',
  'Autonomous AI Threat Reasoning & Attack Categorization',
  'Cross-Tenant Campaign Correlation & Graph Intelligence',
];

export const AuthLayout: React.FC<AuthLayoutProps> = ({
  children,
  heroHeadline,
  heroSubtitle,
  features = DEFAULT_MAILINTEL_FEATURES,
}) => {
  return (
    <div className="h-screen w-full bg-white flex flex-col lg:flex-row overflow-hidden selection:bg-blue-100 selection:text-blue-700 font-sans">
      {/* ========================================================================= */}
      {/* LEFT COLUMN: LOCKED FORENSIC HERO SHOWCASE (Fixed, No Scroll)            */}
      {/* ========================================================================= */}
      <div className="hidden lg:flex lg:w-1/2 h-full flex-shrink-0 relative bg-[#F8FAFC] border-r border-slate-200/90 flex-col justify-center px-12 xl:px-20 py-12 overflow-hidden select-none">
        {/* Crisp Architectural Blueprint Grid */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: `
              linear-gradient(to right, rgba(226, 232, 240, 0.7) 1px, transparent 1px),
              linear-gradient(to bottom, rgba(226, 232, 240, 0.7) 1px, transparent 1px)
            `,
            backgroundSize: '48px 48px',
          }}
        />

        {/* Ambient Radial Cobalt Glow */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: `
              radial-gradient(circle at 45% 30%, rgba(37, 99, 235, 0.08), transparent 60%),
              radial-gradient(circle at 80% 85%, rgba(59, 130, 246, 0.04), transparent 50%)
            `,
          }}
        />

        {/* Master Content Stack — Perfectly Aligned on the Same Left Guide Axis */}
        <div className="relative z-10 max-w-xl w-full mx-auto flex flex-col justify-center space-y-9">
          {/* Top Brand Identity Lockup (Enlarged and Aligned) */}
          <div className="flex flex-col items-start gap-1.5">
            <div className="flex items-center gap-3.5">
              <img
                src="/logo-icon.png"
                alt="MailinTeL"
                className="w-16 h-16 object-contain drop-shadow-sm transition-transform hover:scale-105"
              />
              <img
                src="/wordmark-dark.png"
                alt="MailinTeL"
                className="h-8 xl:h-9 object-contain"
              />
            </div>
            <span className="text-[11px] font-black uppercase tracking-[0.24em] text-blue-600 pl-0.5 pt-0.5">
              EMAIL FORENSICS &amp; THREAT INTELLIGENCE
            </span>
          </div>

          {/* Headline & Subtitle with Generous, Distinct Vertical Spacing */}
          <div className="space-y-4">
            <h1 className="text-4xl xl:text-[46px] font-black text-slate-900 tracking-tight leading-none">
              {heroHeadline || (
                <>
                  <span className="block text-slate-950 font-black">Every Email Has a DNA.</span>
                  <span className="block text-blue-600 font-black mt-3 sm:mt-3.5">Trace the Origin.</span>
                </>
              )}
            </h1>
            <p className="text-sm xl:text-base text-slate-600 leading-relaxed font-normal max-w-lg pt-1">
              {heroSubtitle ||
                'Unmask true physical sender origins, deconstruct multi-hop forwarding footprints, and analyze 5-strand forensic DNA in real time.'}
            </p>
          </div>

          {/* Feature Value Points (Crisply Aligned Checkmarks) */}
          <div className="space-y-3.5 pt-1">
            {features.map((item, idx) => (
              <div key={idx} className="flex items-center gap-3.5 text-sm xl:text-[15px] font-semibold text-slate-700">
                <div className="w-5 h-5 rounded-full border border-blue-400 bg-blue-50/90 flex items-center justify-center shrink-0 text-blue-600 shadow-2xs">
                  <Check className="w-3.5 h-3.5 stroke-[3]" />
                </div>
                <span>{item}</span>
              </div>
            ))}
          </div>

          {/* Bottom Digital Custody & Integrity Seal (Strictly Aligned) */}
          <div className="pt-6 border-t border-slate-200/80 flex items-center gap-2.5 text-xs text-slate-500 font-medium">
            <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>ISO/IEC 27037 Digital Evidence Admissible &amp; SHA-256 Tamper-Proof</span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* RIGHT COLUMN: INDEPENDENTLY SCROLLABLE AUTH FORM CANVAS                  */}
      {/* ========================================================================= */}
      <div className="w-full lg:w-1/2 h-full overflow-y-auto flex flex-col justify-between p-6 sm:p-12 lg:p-16 bg-white">
        {/* Mobile Header (Visible on small screens where left pane is hidden) */}
        <div className="lg:hidden flex items-center justify-between pb-6 mb-4 border-b border-slate-100 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <img src="/logo-icon.png" alt="MailinTeL" className="w-9 h-9 object-contain" />
            <img src="/wordmark-dark.png" alt="MailinTeL" className="h-5 object-contain" />
          </div>
          <span className="text-[9px] font-bold uppercase tracking-wider text-blue-600 bg-blue-50 px-2.5 py-0.5 rounded-full border border-blue-200">
            FORENSICS
          </span>
        </div>

        {/* Centered Form Body */}
        <div className="w-full max-w-md mx-auto my-auto py-6">
          {children}
        </div>

        {/* Global Footer */}
        <div className="pt-8 pb-2 text-center text-xs text-slate-400 font-medium flex-shrink-0">
          &copy; {new Date().getFullYear()} MailinteL. The Intelligence Behind Every Inbox.
        </div>
      </div>
    </div>
  );
};

export default AuthLayout;
