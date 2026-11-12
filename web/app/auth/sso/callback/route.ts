import { relaySso } from '../../../../src/lib/sso-relay';

/** Where the provider sends the browser back; the API signs in and sets the session (src/lib/sso-relay.ts). */
export const dynamic = 'force-dynamic';

export function GET(request: Request): Promise<Response> {
  return relaySso('/api/v1/auth/oidc/callback', request);
}
