/*
 * Single sign-on, browser side (api/src/routes/oidc.ts is the other half).
 *
 * CLAUDE.md rule 1: the browser never talks to the API. So the two browser
 * navigations of an OIDC sign-in land on web's own routes,
 *
 *   /auth/sso/login      -> GET /api/v1/auth/oidc/login     (302 to the provider)
 *   /auth/sso/callback   -> GET /api/v1/auth/oidc/callback  (302 to `next`, session cookies)
 *
 * and each is relayed server to server: the query string and the visitor's
 * cookies go to the API, and the API's redirect and Set-Cookie headers come
 * back as this origin's own response. Two cookies change scope on the way, as
 * in auth-cookies.ts and proxy.ts: the refresh cookie moves to `/` (or the
 * page-load refresh in proxy.ts could never see it), and the sign-in flow
 * cookie moves from the API's /api/v1/auth/oidc to /auth/sso, where the
 * browser will bring it back to the callback.
 *
 * OIDC_REDIRECT_URI is therefore https://<this instance>/auth/sso/callback.
 */

const REFRESH_COOKIE = 'learn_rt';
const FLOW_COOKIE = 'learn_oidc';
export const SSO_WEB_PATH = '/auth/sso';

/** Sign-in can include two calls from the API to the provider (10 s each), so allow for both. */
const TIMEOUT_MS = 25_000;
const UNAVAILABLE = '/login?sso_error=sso_unavailable';

function withPath(header: string, path: string): string {
  return /;\s*Path=/i.test(header) ? header.replace(/;\s*Path=[^;]*/i, `; Path=${path}`) : `${header}; Path=${path}`;
}

/** One API Set-Cookie header, re-scoped for this origin. */
export function rescopeForWeb(header: string): string {
  if (header.startsWith(`${REFRESH_COOKIE}=`)) return withPath(header, '/');
  if (header.startsWith(`${FLOW_COOKIE}=`)) return withPath(header, SSO_WEB_PATH);
  return header;
}

function redirect(location: string, setCookies: string[] = []): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const cookie of setCookies) headers.append('set-cookie', rescopeForWeb(cookie));
  return new Response(null, { status: 302, headers });
}

/**
 * Relays one browser navigation to `apiPath` and answers with the API's
 * redirect. Any failure to reach the API sends the visitor back to the login
 * page with sso_unavailable rather than an error page.
 */
export async function relaySso(apiPath: string, request: Request): Promise<Response> {
  const base = process.env.NEXT_PUBLIC_API_BASE_URL;
  if (!base) return redirect(UNAVAILABLE);
  const search = new URL(request.url).search;
  const forwardedFor = request.headers.get('x-forwarded-for');

  let response: Response;
  try {
    response = await fetch(`${base}${apiPath}${search}`, {
      headers: {
        cookie: request.headers.get('cookie') ?? '',
        ...(forwardedFor ? { 'x-forwarded-for': forwardedFor } : {}),
      },
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    return redirect(UNAVAILABLE);
  }

  const location = response.headers.get('location');
  if (response.status < 300 || response.status >= 400 || !location) return redirect(UNAVAILABLE);
  return redirect(location, response.headers.getSetCookie());
}
