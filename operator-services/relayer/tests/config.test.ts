import { describe, expect, it } from "vitest";
import { configFromEnv } from "../src/index.js";

describe("configFromEnv — bearer-token gate", () => {
  it("relayer_startup_fails_when_bearer_token_unset_without_dev_override", () => {
    // Codex P2 finding: shared/src/http.ts's requireBearer is fail-open when
    // no expected token is configured. The fix lives in configFromEnv —
    // production startup MUST fail closed when RELAYER_BEARER_TOKEN is
    // missing, unless the operator explicitly opted in with
    // RELAYER_ALLOW_NO_AUTH=1.
    expect(() => configFromEnv({})).toThrow(/RELAYER_BEARER_TOKEN is required/);
    expect(() => configFromEnv({})).toThrow(/RELAYER_ALLOW_NO_AUTH=1/);

    // Just providing RELAYER_ALLOW_NO_AUTH unset / "0" must still fail.
    expect(() => configFromEnv({ RELAYER_ALLOW_NO_AUTH: "0" })).toThrow(
      /RELAYER_BEARER_TOKEN is required/,
    );

    // Bearer token present → config loads with bearerAuth on, allowNoAuth off.
    const withToken = configFromEnv({ RELAYER_BEARER_TOKEN: "s3cret" });
    expect(withToken.bearerToken).toBe("s3cret");
    expect(withToken.allowNoAuth).toBe(false);

    // Dev override present → config loads with bearerAuth off, allowNoAuth on.
    const noAuth = configFromEnv({ RELAYER_ALLOW_NO_AUTH: "1" });
    expect(noAuth.bearerToken).toBeUndefined();
    expect(noAuth.allowNoAuth).toBe(true);

    // Both set: token takes precedence as the credential, override flag
    // remains observable (so start.ts can decide whether to log the warn
    // banner). Either way, configFromEnv MUST NOT throw.
    const both = configFromEnv({
      RELAYER_BEARER_TOKEN: "s3cret",
      RELAYER_ALLOW_NO_AUTH: "1",
    });
    expect(both.bearerToken).toBe("s3cret");
    expect(both.allowNoAuth).toBe(true);
  });

  it("inherits standard defaults when bearer or dev override is satisfied", () => {
    const cfg = configFromEnv({ RELAYER_BEARER_TOKEN: "tk" });
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.port).toBe(4300);
    expect(cfg.submitEnabled).toBe(false);
    expect(cfg.bridgePackageAddress).toBeUndefined();
    expect(cfg.adminProfile).toBeUndefined();
  });

  it("propagates submitEnabled and other env knobs", () => {
    const cfg = configFromEnv({
      RELAYER_BEARER_TOKEN: "tk",
      RELAYER_HOST: "0.0.0.0",
      RELAYER_PORT: "9999",
      RELAYER_SUBMIT_ENABLED: "1",
      BRIDGE_PACKAGE_ADDRESS: "0xdeadbeef",
      ADMIN_PROFILE: "alice",
    });
    expect(cfg.host).toBe("0.0.0.0");
    expect(cfg.port).toBe(9999);
    expect(cfg.submitEnabled).toBe(true);
    expect(cfg.bridgePackageAddress).toBe("0xdeadbeef");
    expect(cfg.adminProfile).toBe("alice");
  });
});
