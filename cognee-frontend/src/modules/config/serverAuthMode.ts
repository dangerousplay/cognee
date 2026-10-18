// Server-side only, for the same reason as serverRuntimeConfig: read at
// request time so one image can run with or without an external issuer.
import "server-only";

/** Where /local-login sends the browser when an OIDC issuer owns the accounts. */
export const OIDC_LOGIN_PATH = "/api/v1/auth/oidc/login?return_to=/";

/**
 * COGNEE_AUTH_MODE=oidc (the backend runs with AUTH_MODE=oidc) means there is
 * no password to type: the login page hands over to the backend's OIDC flow,
 * which is served from the same origin as the UI.
 */
export function getOidcLoginPath(): string | null {
  return process.env.COGNEE_AUTH_MODE?.trim().toLowerCase() === "oidc" ? OIDC_LOGIN_PATH : null;
}
