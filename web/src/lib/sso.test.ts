import { describe, expect, it } from 'vitest';
import { ssoErrorMessage, ssoLoginHref } from './sso';

describe('ssoErrorMessage', () => {
  it('explains every code the API sends back', () => {
    for (const code of ['sso_disabled', 'sso_unavailable', 'sso_denied', 'sso_expired', 'sso_state', 'sso_failed', 'sso_unverified', 'sso_no_account']) {
      expect(ssoErrorMessage(code), code).toMatch(/\w/);
    }
  });

  it('tells someone without an account to ask for an invitation', () => {
    expect(ssoErrorMessage('sso_no_account')).toMatch(/invitation/);
  });

  it('shows nothing for no code, an unknown code, or an inherited property name', () => {
    expect(ssoErrorMessage(undefined)).toBeNull();
    expect(ssoErrorMessage('<script>')).toBeNull();
    expect(ssoErrorMessage('toString')).toBeNull();
  });
});

describe('ssoLoginHref', () => {
  it("starts at web's own relay route and carries where to land", () => {
    expect(ssoLoginHref('/')).toBe('/auth/sso/login');
    expect(ssoLoginHref('/courses/intro?tab=2')).toBe('/auth/sso/login?next=%2Fcourses%2Fintro%3Ftab%3D2');
  });
});
