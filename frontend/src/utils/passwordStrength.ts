/**
 * Mirrors app/core/security.py::is_password_strong_enough so the register
 * form can give instant feedback instead of a round-trip 400/422. This is a
 * UX convenience only — the backend re-validates and remains the source of
 * truth; never assume "passed here" means "will be accepted there" (e.g. the
 * server-side common-password list may be extended independently).
 *
 * Deliberately doesn't surface which literal words are blocked — that would
 * just duplicate the backend's blocklist in client-visible source. The hint
 * shown to the user stays generic ("choose a less common password").
 */

// Same small set the backend rejects outright, used only to decide validity —
// never rendered verbatim to the user.
const COMMON_PASSWORDS = new Set(['password', 'password123', 'changeme', 'letmein', 'qwerty123']);

export interface PasswordStrengthResult {
  valid: boolean;
  /** 0-4, for a strength meter. */
  score: number;
  /** User-facing message when invalid; undefined when valid. */
  message?: string;
}

export function checkPasswordStrength(password: string): PasswordStrengthResult {
  if (password.length < 10) {
    return {
      valid: false,
      score: password.length === 0 ? 0 : 1,
      message: 'Password must be at least 10 characters long.',
    };
  }

  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return {
      valid: false,
      score: 1,
      message: 'Password is too common. Please choose a less common password.',
    };
  }

  let categories = 0;
  if (/[a-z]/.test(password)) categories += 1;
  if (/[A-Z]/.test(password)) categories += 1;
  if (/[0-9]/.test(password)) categories += 1;
  if (/[^a-zA-Z0-9]/.test(password)) categories += 1;

  const lengthBonus = password.length >= 14 ? 1 : 0;
  const score = Math.min(4, categories + lengthBonus - (categories >= 3 ? 0 : 1));

  if (categories < 3) {
    return {
      valid: false,
      score: Math.max(1, score),
      message: 'Password must contain at least 3 of: lowercase, uppercase, digit, symbol.',
    };
  }

  return { valid: true, score: Math.max(2, score) };
}
