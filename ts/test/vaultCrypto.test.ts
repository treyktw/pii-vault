import { describe, expect, it } from "vitest";
import {
  decryptVaultValue,
  encryptVaultValue,
  loadKeyring,
  maskVaultValue,
  validateVaultValue,
  type EncryptionContext,
} from "../src/vaultCrypto.js";

// Test keys only: 0x07 * 32 and 0x09 * 32.
const keyringEnv = {
  PII_VAULT_KEYRING: JSON.stringify({
    "1": Buffer.alloc(32, 0x07).toString("base64"),
    "2": Buffer.alloc(32, 0x09).toString("base64"),
  }),
  PII_VAULT_ACTIVE_KEY_VERSION: "2",
};
const keyring = loadKeyring(keyringEnv);

const context: EncryptionContext = {
  tenantId: "tenant_acme_0001",
  vaultId: "0b5c8a52-1f7e-4c1e-9a52-3f5d2a7c9e10",
  ownerType: "client",
  ownerId: "client_0001",
  type: "ssn",
  keyVersion: 2,
};

describe("loadKeyring", () => {
  it("reads the versioned keyring and active version", () => {
    expect(keyring.activeVersion).toBe(2);
    expect([...keyring.keys.keys()].sort()).toEqual([1, 2]);
  });

  it("accepts a single master key for the active version", () => {
    const single = loadKeyring({
      PII_VAULT_MASTER_KEY: Buffer.alloc(32, 1).toString("base64"),
      PII_VAULT_ACTIVE_KEY_VERSION: "3",
    });
    expect(single.activeVersion).toBe(3);
    expect(single.keys.get(3)?.length).toBe(32);
  });

  it.each([
    ["no keys at all", {}],
    ["invalid JSON", { PII_VAULT_KEYRING: "not json" }],
    ["array instead of object", { PII_VAULT_KEYRING: "[]" }],
    ["version zero", { PII_VAULT_KEYRING: JSON.stringify({ "0": Buffer.alloc(32).toString("base64") }) }],
    ["short key", { PII_VAULT_KEYRING: JSON.stringify({ "1": "c2hvcnQ=" }) }],
    [
      "active version missing from keyring",
      {
        PII_VAULT_KEYRING: JSON.stringify({ "1": Buffer.alloc(32).toString("base64") }),
        PII_VAULT_ACTIVE_KEY_VERSION: "2",
      },
    ],
    ["non-integer active version", { ...keyringEnv, PII_VAULT_ACTIVE_KEY_VERSION: "1.5" }],
  ])("fails closed on %s", (_name, env) => {
    expect(() => loadKeyring(env)).toThrow();
  });
});

describe("encrypt / decrypt", () => {
  it("round-trips and returns a masked display hint", () => {
    const sealed = encryptVaultValue("123-45-6789", context, keyring);
    expect(sealed.algorithm).toBe("aes-256-gcm");
    expect(sealed.keyVersion).toBe(2);
    expect(sealed.displayHint).toBe("***-**-6789");
    expect(Buffer.from(sealed.iv, "base64")).toHaveLength(12);
    expect(Buffer.from(sealed.authTag, "base64")).toHaveLength(16);
    expect(decryptVaultValue(sealed, context, keyring)).toBe("123-45-6789");
  });

  it("uses a fresh IV for every write", () => {
    const first = encryptVaultValue("123-45-6789", context, keyring);
    const second = encryptVaultValue("123-45-6789", context, keyring);
    expect(first.iv).not.toBe(second.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });

  it("trims the value before sealing it", () => {
    const sealed = encryptVaultValue("  123-45-6789  ", context, keyring);
    expect(decryptVaultValue(sealed, context, keyring)).toBe("123-45-6789");
  });

  it.each([
    ["tenant", { tenantId: "tenant_globex_0002" }],
    ["vault id", { vaultId: "6f1c2e44-9b0a-4f3d-8e21-5a7b9c0d1e2f" }],
    ["owner type", { ownerType: "user" as const }],
    ["owner id", { ownerId: "client_0002" }],
    ["field type", { type: "tax_id" as const }],
  ])("refuses to open under a different %s", (_name, change) => {
    const sealed = encryptVaultValue("123-45-6789", context, keyring);
    expect(() => decryptVaultValue(sealed, { ...context, ...change }, keyring)).toThrow();
  });

  it("refuses a key-version mismatch between record and context", () => {
    const sealed = encryptVaultValue("123-45-6789", context, keyring);
    expect(() => decryptVaultValue(sealed, { ...context, keyVersion: 1 }, keyring)).toThrow(
      "PII vault key metadata mismatch",
    );
  });

  it("detects a tampered ciphertext, IV or tag", () => {
    const sealed = encryptVaultValue("123-45-6789", context, keyring);
    const flip = (b64: string) => {
      const bytes = Buffer.from(b64, "base64");
      bytes[0] = (bytes[0] ?? 0) ^ 0x01;
      return bytes.toString("base64");
    };
    expect(() => decryptVaultValue({ ...sealed, ciphertext: flip(sealed.ciphertext) }, context, keyring)).toThrow();
    expect(() => decryptVaultValue({ ...sealed, iv: flip(sealed.iv) }, context, keyring)).toThrow();
    expect(() => decryptVaultValue({ ...sealed, authTag: flip(sealed.authTag) }, context, keyring)).toThrow();
  });

  it("keeps records sealed under an older key readable after rotation", () => {
    const v1Context = { ...context, keyVersion: 1 };
    const sealedUnderV1 = encryptVaultValue("123-45-6789", v1Context, keyring);
    // Rotate: v3 becomes active, v1 and v2 remain for reads.
    const rotated = loadKeyring({
      PII_VAULT_KEYRING: JSON.stringify({
        "1": Buffer.alloc(32, 0x07).toString("base64"),
        "2": Buffer.alloc(32, 0x09).toString("base64"),
        "3": Buffer.alloc(32, 0x0b).toString("base64"),
      }),
      PII_VAULT_ACTIVE_KEY_VERSION: "3",
    });
    expect(decryptVaultValue(sealedUnderV1, v1Context, rotated)).toBe("123-45-6789");
    // Retire v1: the old record no longer opens.
    const retired = loadKeyring({
      PII_VAULT_KEYRING: JSON.stringify({ "3": Buffer.alloc(32, 0x0b).toString("base64") }),
      PII_VAULT_ACTIVE_KEY_VERSION: "3",
    });
    expect(() => decryptVaultValue(sealedUnderV1, v1Context, retired)).toThrow(
      "PII vault key version 1 is unavailable",
    );
  });
});

describe("validateVaultValue", () => {
  it.each([
    ["ssn", "123-45-6789"],
    ["drivers_license", "D123-4567-8901"],
    ["date_of_birth", "1990-01-31"],
    ["credit_score", "720"],
    ["monthly_income", "8250.50"],
    ["bank_account", "000123456789"],
    ["tax_id", "12-3456789"],
    ["passport", "X1234567"],
    ["co_buyer_name", "Pat Example"],
    ["custom", "anything at all"],
  ] as const)("accepts a well-formed %s", (type, value) => {
    expect(validateVaultValue(value, type)).toBe(value);
  });

  it.each([
    ["ssn", "000-12-3456"],
    ["ssn", "123-00-4567"],
    ["ssn", "123-45-0000"],
    ["ssn", "12-345-678"],
    ["date_of_birth", "01/31/1990"],
    ["date_of_birth", "2999-01-01"],
    ["credit_score", "299"],
    ["credit_score", "851"],
    ["monthly_income", "-5"],
    ["monthly_income", "100000000.01"],
    ["monthly_income", "1.234"],
    ["co_buyer_name", "bad\u0007name"],
    ["tax_id", "1234"],
    ["custom", "   "],
  ] as const)("rejects a malformed %s (%s)", (type, value) => {
    expect(() => validateVaultValue(value, type)).toThrow();
  });

  it("rejects values over 4 KiB", () => {
    expect(() => validateVaultValue("x".repeat(4097), "custom")).toThrow();
  });
});

describe("maskVaultValue", () => {
  it.each([
    ["ssn", "123-45-6789", "***-**-6789"],
    ["date_of_birth", "1990-01-31", "****-**-31"],
    ["credit_score", "720", "***"],
    ["monthly_income", "8250.50", "••••"],
    ["bank_account", "0001 2345 6789", "••••6789"],
    ["passport", "X1234567", "••••4567"],
    ["custom", "secret", "••••"],
  ] as const)("masks %s", (type, value, masked) => {
    expect(maskVaultValue(value, type)).toBe(masked);
  });
});
