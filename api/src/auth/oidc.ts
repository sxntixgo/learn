import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// Single sign-on (OIDC authorization code flow with PKCE).
//
// WHAT IT IS FOR. A household that already runs an identity provider (here,
// Authentik) signs in there once instead of keeping a second password for this
// instance. It is an additional way into an EXISTING account, never a way to
// make one: the instance stays invite-only (design §12), so the callback looks
// the provider's e-mail up in `users` and refuses when there is no such row.
//
// WHAT IT TRUSTS. The token response comes straight from the issuer's token
// endpoint over TLS, authenticated with the client secret, and the identity is
// read from the same issuer's userinfo endpoint (OIDC Core 3.1.3.7 allows
// skipping ID-token signature checks for a token received this way). So no
// JWT library and no JWKS handling. An e-mail the provider marks unverified
// (`email_verified: false`) is refused: it would let anyone who can type an
// address into their IdP profile become that account here.
//
// WHERE THE FLOW LIVES. This API has no server-side session before sign-in, so
// `state` and the PKCE verifier travel in one short-lived httpOnly cookie
// scoped to the OIDC routes. The browser reaches these routes only through
// the web app's /auth/sso/* relay (web/src/lib/sso-relay.ts), which carries
// the cookie across and re-scopes it to /auth/sso on its own origin. A third party cannot set it in a victim's browser
// (it is httpOnly and SameSite=Lax on our origin), which is what makes the
// state comparison a real CSRF check.
//
// OFF UNLESS ALL FOUR of OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and
// OIDC_REDIRECT_URI are set. OIDC_NAME is the button label ("Sign in with
// <name>"), "SSO" when unset.

export const OIDC_COOKIE = 'learn_oidc';
export const OIDC_COOKIE_PATH = '/api/v1/auth/oidc';
/** Ten minutes to finish signing in at the provider. */
export const OIDC_FLOW_TTL_SECONDS = 600;
export const OIDC_SCOPE = 'openid profile email';

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  name: string;
}

/** The three calls to the provider, behind a seam so tests never touch the network. */
export interface OidcClient {
  discover(): Promise<{ authorization_endpoint: string }>;
  exchangeCode(code: string, verifier: string): Promise<{ access_token: string }>;
  userinfo(accessToken: string): Promise<Record<string, unknown>>;
}

/** Reads the configuration from the environment; null (off) unless all four required values are set. */
// Each read is spelled out in full so tools/src/env-example.test.ts sees it.
export function oidcConfigFromEnv(): OidcConfig | null {
  const issuer = process.env.OIDC_ISSUER?.trim();
  const clientId = process.env.OIDC_CLIENT_ID?.trim();
  const clientSecret = process.env.OIDC_CLIENT_SECRET?.trim();
  const redirectUri = process.env.OIDC_REDIRECT_URI?.trim();
  if (!issuer || !clientId || !clientSecret || !redirectUri) return null;
  return { issuer, clientId, clientSecret, redirectUri, name: process.env.OIDC_NAME?.trim() || 'SSO' };
}

const TIMEOUT_MS = 10_000;

/** The real client: discovery (cached, issuer checked), token exchange, userinfo. */
export function httpOidcClient(config: OidcConfig): OidcClient {
  let discovery: Promise<Record<string, string>> | null = null;

  async function json(response: Response): Promise<Record<string, unknown>> {
    if (!response.ok) throw new Error(`OIDC provider answered ${response.status} for ${response.url}`);
    return (await response.json()) as Record<string, unknown>;
  }

  function discover(): Promise<Record<string, string>> {
    discovery ??= fetch(config.issuer.replace(/\/+$/, '') + '/.well-known/openid-configuration', {
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
      .then(json)
      .then((doc) => {
        if (String(doc.issuer ?? '').replace(/\/+$/, '') !== config.issuer.replace(/\/+$/, '')) {
          throw new Error('OIDC discovery document names a different issuer');
        }
        return doc as Record<string, string>;
      })
      .catch((err: unknown) => {
        discovery = null; // retry on the next sign-in rather than caching the failure
        throw err;
      });
    return discovery;
  }

  return {
    async discover() {
      const doc = await discover();
      return { authorization_endpoint: String(doc.authorization_endpoint) };
    },
    async exchangeCode(code, verifier) {
      const doc = await discover();
      const basic = Buffer.from(
        `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`,
      ).toString('base64');
      const body = await json(
        await fetch(String(doc.token_endpoint), {
          method: 'POST',
          headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: config.redirectUri,
            code_verifier: verifier,
          }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        }),
      );
      if (typeof body.access_token !== 'string') throw new Error('OIDC token response has no access_token');
      return { access_token: body.access_token };
    },
    async userinfo(accessToken) {
      const doc = await discover();
      return json(
        await fetch(String(doc.userinfo_endpoint), {
          headers: { Authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(TIMEOUT_MS),
        }),
      );
    },
  };
}

export interface OidcFlow {
  state: string;
  verifier: string;
  next: string;
}

/** A fresh state + verifier pair and the S256 challenge for it (RFC 7636). */
export function newFlow(next: string): { flow: OidcFlow; challenge: string } {
  const flow = { state: randomBytes(32).toString('base64url'), verifier: randomBytes(48).toString('base64url'), next };
  return { flow, challenge: createHash('sha256').update(flow.verifier).digest('base64url') };
}

export function encodeFlow(flow: OidcFlow): string {
  return Buffer.from(JSON.stringify(flow), 'utf8').toString('base64url');
}

/** The flow from the cookie, or null when it is missing or not one of ours. */
export function decodeFlow(raw: unknown): OidcFlow | null {
  if (typeof raw !== 'string' || raw === '') return null;
  try {
    const value = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as Partial<OidcFlow>;
    if (typeof value.state !== 'string' || typeof value.verifier !== 'string' || typeof value.next !== 'string') {
      return null;
    }
    return { state: value.state, verifier: value.verifier, next: safeNextPath(value.next) };
  } catch {
    return null;
  }
}

/** Constant-time comparison of the state the provider returned with the one this browser holds. */
export function sameState(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// eslint-disable-next-line no-control-regex -- refusing control characters is the point
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

/**
 * Where to land after signing in: a same-site relative path, else '/'. The
 * same rules as the web app's sanitizeNextPath (web/src/lib/next-path.ts),
 * repeated here because this value goes into a Location header the API writes.
 */
export function safeNextPath(raw: unknown): string {
  if (typeof raw !== 'string' || raw === '' || CONTROL_CHARACTERS.test(raw)) return '/';
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return '/';
  const segments = (raw.split(/[?#]/, 1)[0] ?? raw).split('/');
  if (segments.includes('..') || segments.includes('.')) return '/';
  return raw;
}
