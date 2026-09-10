import DOMPurify from 'dompurify';
// MVP-05 fix: dompurify >= 3.0 ships its own bundled TypeScript types and no
// longer needs (or is compatible with) the separate @types/dompurify package
// (removed from package.json). Importing the `Config` type as a named export
// from 'dompurify' itself — rather than referencing it as `DOMPurify.Config`,
// which was the shape the old @types/dompurify package used — is what the
// installed module actually exports, so this no longer produces TS2769.
import type { Config } from 'dompurify';

/**
 * SECURITY: html_body comes straight from an analyzed email — by definition
 * attacker-controlled, often actively malicious (phishing/BEC payloads).
 * Rendering it with dangerouslySetInnerHTML unsanitized is a stored XSS
 * vector against the analyst viewing it, and could exfiltrate the bearer
 * token this app keeps in localStorage (see services/authStorage.ts).
 *
 * This sanitizer is intentionally stricter than DOMPurify's defaults for a
 * general-purpose site, because the threat model here is "every email is
 * hostile until proven otherwise":
 *   - No script/style/iframe/object/embed/form/link/meta/base tags.
 *   - No event handlers (DOMPurify strips on* by default).
 *   - No remote resource loading (img/background/etc.) — a phishing email
 *     that loads a remote image the moment an analyst opens it is a classic
 *     "confirmed this address is being read" tracking pixel. src/srcset/
 *     background attributes are stripped rather than rendered live.
 */
DOMPurify.addHook('uponSanitizeAttribute', (_node, data) => {
  if (['src', 'srcset', 'background', 'poster'].includes(data.attrName)) {
    const value = data.attrValue || '';
    // Keep only inert, non-network-fetching values.
    if (!value.startsWith('data:') && !value.startsWith('cid:')) {
      data.keepAttr = false;
    }
  }
});

const SANITIZE_CONFIG: Config = {
  FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'link', 'meta', 'base'],
  FORBID_ATTR: ['srcdoc'],
  ALLOW_DATA_ATTR: false,
  // Rely on DOMPurify's default ALLOWED_URI_REGEXP, which already rejects
  // javascript:/data:(non-image) hrefs — no need to loosen or tighten it.
};

export function sanitizeEmailHtml(rawHtml: string): string {
  return DOMPurify.sanitize(rawHtml, SANITIZE_CONFIG) as unknown as string;
}
