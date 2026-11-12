/*
 * Single sign-on on the login page (api/src/routes/oidc.ts).
 *
 * The SSO button is a plain link, not a fetch: the browser itself has to go
 * to the provider and back. It goes to web's own /auth/sso/login, which
 * relays to the API (src/lib/sso-relay.ts), so the browser never talks to the
 * API directly.
 *
 * Failures come back as /login?sso_error=<code>. Only known codes are shown;
 * anything else in the address is ignored rather than echoed.
 */

const MESSAGES: Record<string, string> = {
  sso_disabled: 'Single sign-on is not set up on this instance.',
  sso_unavailable: 'The sign-in provider could not be reached. Try again, or use your password.',
  sso_denied: 'Sign-in was cancelled at the provider.',
  sso_expired: 'That sign-in took too long or was started in another browser. Please try again.',
  sso_state: 'That sign-in could not be verified. Please try again.',
  sso_failed: 'The sign-in provider did not confirm who you are. Please try again.',
  sso_unverified: 'Your e-mail address is not verified at the sign-in provider.',
  sso_no_account: 'There is no account here with your e-mail address. Ask for an invitation first.',
};

/** The message for an sso_error code, or null for no code or an unknown one. */
export function ssoErrorMessage(code: string | null | undefined): string | null {
  if (typeof code !== 'string') return null;
  return Object.hasOwn(MESSAGES, code) ? MESSAGES[code]! : null;
}

/** Where the "Sign in with …" link starts the flow, carrying where to land afterwards. */
export function ssoLoginHref(next: string): string {
  return next === '/' ? '/auth/sso/login' : `/auth/sso/login?next=${encodeURIComponent(next)}`;
}
