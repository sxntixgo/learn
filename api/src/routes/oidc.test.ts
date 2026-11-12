import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../index.ts';
import { setPool, closePool } from '../db.ts';
import { ACCESS_COOKIE, REFRESH_COOKIE } from '../auth/cookies.ts';
import { OIDC_COOKIE, OIDC_COOKIE_PATH, type OidcClient, type OidcConfig } from '../auth/oidc.ts';

const { Pool } = pg;

const connectionString = process.env.TEST_DATABASE_URL;
if (!connectionString) {
  throw new Error('TEST_DATABASE_URL is not set — required to run oidc.test.ts');
}

const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../db/migrations');
const pool = new Pool({ connectionString });

async function applyMigrations(): Promise<void> {
  await pool.query(`
    create table if not exists schema_migrations (
      version     text primary key,
      applied_at  timestamptz not null default now()
    )
  `);
  const files = (await readdir(migrationsDir)).filter((f) => f.endsWith('.sql')).sort();
  const { rows } = await pool.query<{ version: string }>('select version from schema_migrations');
  const applied = new Set(rows.map((r) => r.version));
  for (const file of files) {
    const version = file.replace(/\.sql$/, '');
    if (applied.has(version)) continue;
    const sql = await readFile(path.join(migrationsDir, file), 'utf8');
    try {
      await pool.query(sql);
      await pool.query('insert into schema_migrations (version) values ($1) on conflict do nothing', [version]);
    } catch (err) {
      if ((err as { code?: string }).code !== '42P07') throw err;
    }
  }
}

const RUN_ID = `${Date.now()}${Math.random().toString(36).slice(2, 6)}`.replace(/[^a-z0-9]/gi, '').toLowerCase();
const MEMBER_EMAIL = `sso-member-${RUN_ID}@example.test`;
const STRANGER_EMAIL = `sso-stranger-${RUN_ID}@example.test`;

const CONFIG: OidcConfig = {
  issuer: 'https://idp.example.test/application/o/learn/',
  clientId: 'learn-client',
  clientSecret: 'not-a-real-secret',
  redirectUri: 'https://learn.example.test/auth/sso/callback',
  name: 'Authentik',
};

/** A fake identity provider: records what the API asked and answers with `identity`. */
function fakeIdp(identity: Record<string, unknown> | (() => never)) {
  const calls: { code: string; verifier: string }[] = [];
  const client: OidcClient = {
    async discover() {
      return { authorization_endpoint: 'https://idp.example.test/application/o/authorize/' };
    },
    async exchangeCode(code, verifier) {
      calls.push({ code, verifier });
      return { access_token: 'idp-access-token' };
    },
    async userinfo(accessToken) {
      expect(accessToken).toBe('idp-access-token');
      if (typeof identity === 'function') identity();
      return identity as Record<string, unknown>;
    },
  };
  return { client, calls };
}

function cookieOf(response: { cookies: unknown[] }, name: string): Record<string, unknown> | undefined {
  return (response.cookies as Array<Record<string, unknown>>).find((c) => c.name === name);
}

let memberId: string;
const servers: FastifyInstance[] = [];

async function serverWith(config: OidcConfig | null, client: OidcClient): Promise<FastifyInstance> {
  const s = await buildServer({ trustProxy: false, oidc: { config, client } });
  servers.push(s);
  return s;
}

/** Starts a sign-in: returns the flow cookie and the authorize URL the browser was sent to. */
async function begin(s: FastifyInstance, next?: string) {
  const res = await s.inject({
    method: 'GET',
    url: '/api/v1/auth/oidc/login' + (next === undefined ? '' : `?next=${encodeURIComponent(next)}`),
  });
  const flow = cookieOf(res, OIDC_COOKIE);
  return { res, flow: String(flow?.value ?? ''), location: new URL(String(res.headers.location)) };
}

async function callback(s: FastifyInstance, query: string, flowCookie?: string) {
  return s.inject({
    method: 'GET',
    url: `/api/v1/auth/oidc/callback?${query}`,
    cookies: flowCookie === undefined ? {} : { [OIDC_COOKIE]: flowCookie },
  });
}

describe('single sign-on (OIDC authorization code + PKCE)', () => {
  beforeAll(async () => {
    await applyMigrations();
    setPool(pool);
    const { rows } = await pool.query<{ id: string }>(
      `insert into users (email, handle, display_name, password_hash) values ($1, $2, 'SSO Member', null) returning id`,
      [MEMBER_EMAIL, `ssomem${RUN_ID}`],
    );
    memberId = rows[0]!.id;
    await pool.query(`insert into user_roles (user_id, role) values ($1, 'student')`, [memberId]);
  });

  afterAll(async () => {
    for (const s of servers) await s.close();
    // refresh_tokens and user_roles cascade from users; audit_log is append-only
    // (0005) and outlives the account, as in auth.test.ts.
    await pool.query(`delete from users where email in ($1, $2)`, [MEMBER_EMAIL, STRANGER_EMAIL]);
    await closePool();
  });

  describe('GET /api/v1/auth/oidc/config', () => {
    it('says it is off when it is not configured', async () => {
      const s = await serverWith(null, fakeIdp({}).client);
      const res = await s.inject({ method: 'GET', url: '/api/v1/auth/oidc/config' });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ enabled: false, name: null });
    });

    it("gives the provider's name for the button when it is on", async () => {
      const s = await serverWith(CONFIG, fakeIdp({}).client);
      const res = await s.inject({ method: 'GET', url: '/api/v1/auth/oidc/config' });
      expect(res.json()).toEqual({ enabled: true, name: 'Authentik' });
    });
  });

  describe('GET /api/v1/auth/oidc/login', () => {
    it('refuses back to the login page when it is off', async () => {
      const s = await serverWith(null, fakeIdp({}).client);
      const res = await s.inject({ method: 'GET', url: '/api/v1/auth/oidc/login' });
      expect(res.statusCode).toBe(302);
      expect(res.headers.location).toBe('/login?sso_error=sso_disabled');
    });

    it('sends the browser to the provider with state and an S256 challenge, and keeps the verifier in a scoped httpOnly cookie', async () => {
      const s = await serverWith(CONFIG, fakeIdp({}).client);
      const { res, location } = await begin(s);
      expect(res.statusCode).toBe(302);
      expect(location.origin + location.pathname).toBe('https://idp.example.test/application/o/authorize/');
      const q = location.searchParams;
      expect(q.get('response_type')).toBe('code');
      expect(q.get('client_id')).toBe('learn-client');
      expect(q.get('redirect_uri')).toBe(CONFIG.redirectUri);
      expect(q.get('scope')).toBe('openid profile email');
      expect(q.get('code_challenge_method')).toBe('S256');
      expect(q.get('state')).toMatch(/^[A-Za-z0-9_-]{40,}$/);

      const flow = cookieOf(res, OIDC_COOKIE)!;
      expect(flow.httpOnly).toBe(true);
      expect(flow.secure).toBe(true);
      expect(flow.sameSite).toBe('Lax');
      expect(flow.path).toBe(OIDC_COOKIE_PATH);
      expect(Number(flow.maxAge)).toBeLessThanOrEqual(600);

      // The cookie's verifier is the one the challenge was made from.
      const saved = JSON.parse(Buffer.from(String(flow.value), 'base64url').toString('utf8')) as Record<string, string>;
      expect(saved.state).toBe(q.get('state'));
      const challenge = createHash('sha256').update(saved.verifier!).digest('base64url');
      expect(q.get('code_challenge')).toBe(challenge);
      // The client secret never goes to the browser.
      expect(location.search).not.toContain('not-a-real-secret');
    });

    it('answers sso_unavailable when the provider cannot be reached', async () => {
      const broken: OidcClient = { ...fakeIdp({}).client, discover: () => Promise.reject(new Error('down')) };
      const s = await serverWith(CONFIG, broken);
      const res = await s.inject({ method: 'GET', url: '/api/v1/auth/oidc/login' });
      expect(res.headers.location).toBe('/login?sso_error=sso_unavailable');
    });
  });

  describe('GET /api/v1/auth/oidc/callback', () => {
    it('signs in the existing account with that e-mail and lands where the reader was headed', async () => {
      const idp = fakeIdp({ email: MEMBER_EMAIL.toUpperCase(), email_verified: true });
      const s = await serverWith(CONFIG, idp.client);
      const { flow, location } = await begin(s, '/courses/intro');
      const state = location.searchParams.get('state')!;

      const res = await callback(s, `code=abc&state=${state}`, flow);
      expect(res.statusCode).toBe(302);
      expect(res.headers.location).toBe('/courses/intro');
      expect(cookieOf(res, ACCESS_COOKIE)?.value).toBeTruthy();
      expect(cookieOf(res, REFRESH_COOKIE)?.value).toBeTruthy();
      // The flow cookie is single-use.
      expect(cookieOf(res, OIDC_COOKIE)?.value).toBe('');

      // The code went to the token endpoint with the verifier from this browser's cookie.
      const saved = JSON.parse(Buffer.from(flow, 'base64url').toString('utf8')) as { verifier: string };
      expect(idp.calls).toEqual([{ code: 'abc', verifier: saved.verifier }]);

      const audit = await pool.query<{ meta: { method?: string } }>(
        `select meta from audit_log where actor_id = $1 and action = 'auth.login'`,
        [memberId],
      );
      expect(audit.rows.map((r) => r.meta.method)).toEqual(['oidc']);

      // The session it started is a real one.
      const me = await s.inject({
        method: 'GET',
        url: '/api/v1/me',
        cookies: { [ACCESS_COOKIE]: String(cookieOf(res, ACCESS_COOKIE)!.value) },
      });
      expect(me.statusCode).toBe(200);
    });

    it('never creates an account: an e-mail with no account here is refused', async () => {
      const s = await serverWith(CONFIG, fakeIdp({ email: STRANGER_EMAIL, email_verified: true }).client);
      const { flow, location } = await begin(s);
      const res = await callback(s, `code=abc&state=${location.searchParams.get('state')}`, flow);
      expect(res.headers.location).toBe('/login?sso_error=sso_no_account');
      expect(cookieOf(res, ACCESS_COOKIE)).toBeUndefined();
      const { rowCount } = await pool.query('select 1 from users where email = $1', [STRANGER_EMAIL]);
      expect(rowCount).toBe(0);
    });

    it('refuses an e-mail the provider says is unverified', async () => {
      const s = await serverWith(CONFIG, fakeIdp({ email: MEMBER_EMAIL, email_verified: false }).client);
      const { flow, location } = await begin(s);
      const res = await callback(s, `code=abc&state=${location.searchParams.get('state')}`, flow);
      expect(res.headers.location).toBe('/login?sso_error=sso_unverified');
      expect(cookieOf(res, ACCESS_COOKIE)).toBeUndefined();
    });

    it('refuses a state that does not match this browser (login CSRF)', async () => {
      const idp = fakeIdp({ email: MEMBER_EMAIL, email_verified: true });
      const s = await serverWith(CONFIG, idp.client);
      const { flow } = await begin(s);
      const res = await callback(s, 'code=abc&state=someone-elses-state', flow);
      expect(res.headers.location).toBe('/login?sso_error=sso_state');
      expect(cookieOf(res, ACCESS_COOKIE)).toBeUndefined();
      expect(idp.calls).toEqual([]);
    });

    it('treats a missing or unreadable flow cookie as an expired sign-in', async () => {
      const s = await serverWith(CONFIG, fakeIdp({ email: MEMBER_EMAIL, email_verified: true }).client);
      expect((await callback(s, 'code=abc&state=x')).headers.location).toBe('/login?sso_error=sso_expired');
      expect((await callback(s, 'code=abc&state=x', 'not-json')).headers.location).toBe('/login?sso_error=sso_expired');
    });

    it('reports a refusal at the provider as sso_denied', async () => {
      const s = await serverWith(CONFIG, fakeIdp({}).client);
      const { flow } = await begin(s);
      const res = await callback(s, 'error=access_denied', flow);
      expect(res.headers.location).toBe('/login?sso_error=sso_denied');
    });

    it('reports a failed exchange as sso_failed', async () => {
      const s = await serverWith(
        CONFIG,
        fakeIdp(() => {
          throw new Error('userinfo 500');
        }).client,
      );
      const { flow, location } = await begin(s);
      const res = await callback(s, `code=abc&state=${location.searchParams.get('state')}`, flow);
      expect(res.headers.location).toBe('/login?sso_error=sso_failed');
    });

    it('never redirects off-site, whatever next says', async () => {
      const s = await serverWith(CONFIG, fakeIdp({ email: MEMBER_EMAIL, email_verified: true }).client);
      for (const next of ['//evil.example', 'https://evil.example/x', '/\\evil.example', '/a/../../b']) {
        const { flow, location } = await begin(s, next);
        const res = await callback(s, `code=abc&state=${location.searchParams.get('state')}`, flow);
        expect(res.headers.location).toBe('/');
      }
    });

    it('is off when not configured', async () => {
      const s = await serverWith(null, fakeIdp({}).client);
      const res = await callback(s, 'code=abc&state=x', 'whatever');
      expect(res.headers.location).toBe('/login?sso_error=sso_disabled');
    });
  });
});
