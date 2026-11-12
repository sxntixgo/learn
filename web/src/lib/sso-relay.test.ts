import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { relaySso, rescopeForWeb } from './sso-relay';

const API = 'http://api.internal:3001';

function apiAnswers(status: number, headers: [string, string][]) {
  const fetchMock = vi.fn(async () => {
    const h = new Headers();
    for (const [k, v] of headers) h.append(k, v);
    return new Response(null, { status, headers: h });
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('rescopeForWeb', () => {
  it('moves the refresh cookie to / and the flow cookie to /auth/sso, and leaves the rest alone', () => {
    expect(rescopeForWeb('learn_rt=abc; Path=/api/v1/auth; HttpOnly; Secure')).toBe('learn_rt=abc; Path=/; HttpOnly; Secure');
    expect(rescopeForWeb('learn_oidc=x; Max-Age=600; Path=/api/v1/auth/oidc; HttpOnly')).toBe(
      'learn_oidc=x; Max-Age=600; Path=/auth/sso; HttpOnly',
    );
    expect(rescopeForWeb('learn_at=t; Path=/; HttpOnly')).toBe('learn_at=t; Path=/; HttpOnly');
  });
});

describe('relaySso', () => {
  beforeEach(() => vi.stubEnv('NEXT_PUBLIC_API_BASE_URL', API));
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('passes the query and the visitor’s cookies to the API, and its redirect and cookies back', async () => {
    const fetchMock = apiAnswers(302, [
      ['location', '/courses/intro'],
      ['set-cookie', 'learn_at=t; Path=/; HttpOnly; Secure; SameSite=Lax'],
      ['set-cookie', 'learn_rt=r; Path=/api/v1/auth; HttpOnly; Secure; SameSite=Lax'],
      ['set-cookie', 'learn_oidc=; Max-Age=0; Path=/api/v1/auth/oidc'],
    ]);
    const res = await relaySso(
      '/api/v1/auth/oidc/callback',
      new Request('https://learn.example.test/auth/sso/callback?code=c&state=s', {
        headers: { cookie: 'learn_oidc=flow', 'x-forwarded-for': '10.0.0.9' },
      }),
    );

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${API}/api/v1/auth/oidc/callback?code=c&state=s`);
    expect(init.redirect).toBe('manual');
    expect(init.headers).toMatchObject({ cookie: 'learn_oidc=flow', 'x-forwarded-for': '10.0.0.9' });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/courses/intro');
    expect(res.headers.getSetCookie()).toEqual([
      'learn_at=t; Path=/; HttpOnly; Secure; SameSite=Lax',
      'learn_rt=r; Path=/; HttpOnly; Secure; SameSite=Lax',
      'learn_oidc=; Max-Age=0; Path=/auth/sso',
    ]);
  });

  it('passes an off-site redirect to the provider through untouched', async () => {
    apiAnswers(302, [['location', 'https://idp.example.test/authorize?x=1']]);
    const res = await relaySso('/api/v1/auth/oidc/login', new Request('https://learn.example.test/auth/sso/login'));
    expect(res.headers.get('location')).toBe('https://idp.example.test/authorize?x=1');
  });

  it('sends the visitor back to the login page when the API cannot be reached or does not redirect', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new Error('ECONNREFUSED'))));
    const down = await relaySso('/api/v1/auth/oidc/login', new Request('https://learn.example.test/auth/sso/login'));
    expect(down.headers.get('location')).toBe('/login?sso_error=sso_unavailable');

    apiAnswers(500, []);
    const broken = await relaySso('/api/v1/auth/oidc/login', new Request('https://learn.example.test/auth/sso/login'));
    expect(broken.status).toBe(302);
    expect(broken.headers.get('location')).toBe('/login?sso_error=sso_unavailable');
  });
});
