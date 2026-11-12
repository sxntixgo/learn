import type { FastifyInstance, FastifyReply } from 'fastify';
import { getPool } from '../db.ts';
import { loadRoles } from '../auth/roles.ts';
import { getSigningKeys, type SigningKeys } from '../auth/keys.ts';
import {
  OIDC_COOKIE,
  OIDC_COOKIE_PATH,
  OIDC_FLOW_TTL_SECONDS,
  OIDC_SCOPE,
  decodeFlow,
  encodeFlow,
  httpOidcClient,
  newFlow,
  oidcConfigFromEnv,
  safeNextPath,
  sameState,
  type OidcClient,
  type OidcConfig,
} from '../auth/oidc.ts';
import { startSession } from './auth.ts';

// Single sign-on routes (see auth/oidc.ts for what is trusted and why).
//
//   GET /api/v1/auth/oidc/config     {enabled, name} for the login page's button.
//   GET /api/v1/auth/oidc/login      302 to the provider; state + verifier in a cookie.
//   GET /api/v1/auth/oidc/callback   code -> token -> userinfo -> EXISTING account
//                                    by e-mail -> the same session a password login
//                                    starts -> 302 to `next`.
//
// Like the password routes these run before there is an actor, so there is
// nothing for can() to decide: the provider's answer IS the authentication.
// Every failure lands on /login?sso_error=<code>, one code per thing the
// reader could act on, and never says whether an e-mail has an account beyond
// the one case the reader must be told (sso_no_account: ask for an invite).

export interface OidcRouteDeps {
  /** Test seam: the configuration (null = off) and the provider client. */
  oidc?: { config: OidcConfig | null; client: OidcClient };
  signingKeys?: SigningKeys;
}

const FLOW_COOKIE = { httpOnly: true, secure: true, sameSite: 'lax', path: OIDC_COOKIE_PATH } as const;

function fail(reply: FastifyReply, code: string): FastifyReply {
  reply.clearCookie(OIDC_COOKIE, FLOW_COOKIE);
  return reply.redirect(`/login?sso_error=${code}`, 302);
}

export function registerOidcRoutes(fastify: FastifyInstance, deps: OidcRouteDeps = {}): void {
  const config = deps.oidc ? deps.oidc.config : oidcConfigFromEnv();
  const client = deps.oidc?.client ?? (config ? httpOidcClient(config) : null);
  const keys = () => deps.signingKeys ?? getSigningKeys();

  fastify.get('/api/v1/auth/oidc/config', async () => ({
    enabled: config !== null,
    name: config?.name ?? null,
  }));

  fastify.get<{ Querystring: { next?: string } }>('/api/v1/auth/oidc/login', async (request, reply) => {
    if (!config || !client) return fail(reply, 'sso_disabled');
    let authorizationEndpoint: string;
    try {
      authorizationEndpoint = (await client.discover()).authorization_endpoint;
    } catch (err) {
      request.log.error({ err }, 'OIDC discovery failed');
      return fail(reply, 'sso_unavailable');
    }

    const { flow, challenge } = newFlow(safeNextPath(request.query.next));
    reply.setCookie(OIDC_COOKIE, encodeFlow(flow), { ...FLOW_COOKIE, maxAge: OIDC_FLOW_TTL_SECONDS });

    const target = new URL(authorizationEndpoint);
    target.search = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: OIDC_SCOPE,
      state: flow.state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString();
    return reply.redirect(target.toString(), 302);
  });

  fastify.get<{ Querystring: { code?: string; state?: string; error?: string } }>(
    '/api/v1/auth/oidc/callback',
    async (request, reply) => {
      if (!config || !client) return fail(reply, 'sso_disabled');
      if (request.query.error) return fail(reply, 'sso_denied');

      const flow = decodeFlow(request.cookies?.[OIDC_COOKIE]);
      if (!flow) return fail(reply, 'sso_expired');
      const { code, state } = request.query;
      if (typeof code !== 'string' || code === '' || typeof state !== 'string' || !sameState(state, flow.state)) {
        return fail(reply, 'sso_state');
      }

      let info: Record<string, unknown>;
      try {
        const tokens = await client.exchangeCode(code, flow.verifier);
        info = await client.userinfo(tokens.access_token);
      } catch (err) {
        request.log.error({ err }, 'OIDC code exchange or userinfo failed');
        return fail(reply, 'sso_failed');
      }

      const email = typeof info.email === 'string' ? info.email.trim().toLowerCase() : '';
      if (email === '') return fail(reply, 'sso_failed');
      if (info.email_verified === false) return fail(reply, 'sso_unverified');

      const pool = getPool();
      const { rows } = await pool.query<{ id: string; handle: string | null }>(
        'select id, handle from users where email = $1',
        [email],
      );
      const user = rows[0];
      if (!user) {
        request.log.warn('OIDC sign-in for an e-mail with no account here');
        return fail(reply, 'sso_no_account');
      }

      const roles = await loadRoles(pool, user.id);
      await startSession(reply, keys(), user, roles, null);
      await pool.query(
        `insert into audit_log (actor_id, action, target, meta) values ($1, 'auth.login', $2, $3::jsonb)`,
        [user.id, user.handle, JSON.stringify({ method: 'oidc', provider: config.name, roles })],
      );

      reply.clearCookie(OIDC_COOKIE, FLOW_COOKIE);
      return reply.redirect(flow.next, 302);
    },
  );
}
