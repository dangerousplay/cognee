import { redirect } from "next/navigation";

import LocalLoginPage from "../page";
import { getOidcLoginPath, OIDC_LOGIN_PATH } from "@/modules/config/serverAuthMode";

jest.mock("next/navigation", () => ({
  redirect: jest.fn(() => {
    throw new Error("NEXT_REDIRECT");
  }),
}));

describe("local login under an OIDC issuer (COG-01)", () => {
  const original = process.env.COGNEE_AUTH_MODE;

  afterEach(() => {
    process.env.COGNEE_AUTH_MODE = original;
    jest.clearAllMocks();
  });

  it("sends the browser to the backend's OIDC login on the same origin", () => {
    process.env.COGNEE_AUTH_MODE = "oidc";

    expect(() => LocalLoginPage()).toThrow("NEXT_REDIRECT");
    expect(redirect).toHaveBeenCalledWith("/api/v1/auth/oidc/login?return_to=/");
  });

  it("is case and whitespace tolerant", () => {
    process.env.COGNEE_AUTH_MODE = " OIDC ";

    expect(getOidcLoginPath()).toBe(OIDC_LOGIN_PATH);
  });

  it("keeps the password form when no auth mode is set", () => {
    delete process.env.COGNEE_AUTH_MODE;

    expect(getOidcLoginPath()).toBeNull();
  });
});
