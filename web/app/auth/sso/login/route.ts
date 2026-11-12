import { relaySso } from '../../../../src/lib/sso-relay';

/** Starts single sign-on: relays to the API, which redirects to the provider (src/lib/sso-relay.ts). */
export const dynamic = 'force-dynamic';

export function GET(request: Request): Promise<Response> {
  return relaySso('/api/v1/auth/oidc/login', request);
}
