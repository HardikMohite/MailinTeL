import React from 'react';

export interface BrandLogoProps {
  /**
   * sidebar — icon + wordmark lockup for the dark sidebar header
   * header  — small icon-only mark for the light top header
   * hero    — large icon + wordmark + tagline for landing/empty states
   * mark    — icon only, no text, for compact placements
   */
  variant?: 'sidebar' | 'header' | 'hero' | 'mark';
  showTagline?: boolean;
  className?: string;
  onClick?: () => void;
  /**
   * Which background this sits on. Controls whether the white-text or
   * dark-text wordmark/tagline assets are used — never approximate this
   * with CSS filters, always swap to the matching source asset.
   */
  surface?: 'light' | 'dark';
}

/**
 * Renders the official MailinteL logo assets:
 *  - /logo-icon.png        shield + envelope + fingerprint mark (transparent)
 *  - /wordmark-dark.png    "MailinteL" in navy/black — for light surfaces
 *  - /wordmark-white.png   "MailinteL" in white — for dark/navy surfaces
 *  - /tagline-dark.png     "Intelligence behind each Inbox" — for light surfaces
 *  - /tagline-white.png    "Intelligence behind each Inbox" — for dark surfaces
 * Never reconstruct the wordmark from styled spans/text — always use these
 * source files so the brand stays pixel-accurate.
 */
export const BrandLogo: React.FC<BrandLogoProps> = ({
  variant = 'sidebar',
  showTagline = true,
  className = '',
  onClick,
  surface,
}) => {
  const defaultSurface = variant === 'sidebar' ? 'dark' : 'light';
  const bg = surface ?? defaultSurface;
  const wordmark = bg === 'dark' ? '/wordmark-white.png' : '/wordmark-dark.png';
  const tagline = bg === 'dark' ? '/tagline-white.png' : '/tagline-dark.png';

  if (variant === 'mark') {
    return (
      <img
        src="/logo-icon.png"
        alt="MailinteL"
        className={`object-contain ${className}`}
        onClick={onClick}
      />
    );
  }

  if (variant === 'header') {
    return (
      <button type="button" onClick={onClick} className={`inline-flex items-center gap-2 ${className}`}>
        <img src="/logo-icon.png" alt="MailinteL" className="w-7 h-7 object-contain" />
        <img src={wordmark} alt="MailinteL" className="h-4 object-contain" />
      </button>
    );
  }

  if (variant === 'hero') {
    return (
      <div className={`flex flex-col items-center text-center select-none ${className}`}>
        <img
          src="/logo-icon.png"
          alt="MailinteL Mark"
          className="w-20 h-20 sm:w-22 sm:h-22 object-contain drop-shadow-sm transition-transform duration-300 hover:scale-105"
        />
        <img src={wordmark} alt="MailinteL" className="h-9 sm:h-10 object-contain mt-3" />
        {showTagline && (
          <img
            src={tagline}
            alt="Intelligence behind each Inbox"
            className="h-3 sm:h-3.5 object-contain mt-2 opacity-90"
          />
        )}
      </div>
    );
  }

  // sidebar (default)
  return (
    <button type="button" onClick={onClick} className={`w-full flex items-center gap-2.5 text-left ${className}`}>
      <img src="/logo-icon.png" alt="MailinteL" className="w-9 h-9 object-contain shrink-0" />
      <div className="min-w-0">
        <img src={wordmark} alt="MailinteL" className="h-4 object-contain" />
        {showTagline && (
          <img src={tagline} alt="Intelligence behind each Inbox" className="h-2 object-contain mt-1.5" />
        )}
      </div>
    </button>
  );
};

export default BrandLogo;
