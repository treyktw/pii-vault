import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from "node:crypto";

export type VaultPiiType =
  | "ssn"
  | "drivers_license"
  | "date_of_birth"
  | "credit_score"
  | "monthly_income"
  | "housing_payment"
  | "preapproval_max"
  | "trade_payoff"
  | "co_buyer_name"
  | "co_buyer_score"
  | "bank_account"
  | "tax_id"
  | "passport"
  | "custom";

export type VaultOwnerType = "user" | "client" | "deal" | "organization";

export type EncryptionContext = {
  tenantId: string;
  vaultId: string;
  ownerType: VaultOwnerType;
  ownerId: string;
  type: VaultPiiType;
  keyVersion: number;
};

export type EncryptedVaultValue = {
  ciphertext: string;
  iv: string;
  authTag: string;
  algorithm: "aes-256-gcm";
  keyVersion: number;
  displayHint: string;
};

type Keyring = Map<number, Buffer>;

/** Master keys by version, plus the version new writes use. */
export type VaultKeyring = { activeVersion: number; keys: Keyring };

type KeyringEnv = Record<string, string | undefined>;

function decodeKey(value: string, version: number): Buffer {
  const key = Buffer.from(value, "base64");
  if (key.length !== 32) {
    throw new Error(`PII vault key version ${version} must decode to 32 bytes`);
  }
  return key;
}

/**
 * Reads PII_VAULT_KEYRING ({"1":"<base64 32 bytes>", ...}) and
 * PII_VAULT_ACTIVE_KEY_VERSION. Fails closed: a missing or malformed key is an
 * error, never a fallback.
 */
export function loadKeyring(env: KeyringEnv = process.env): VaultKeyring {
  const activeVersion = Number(env.PII_VAULT_ACTIVE_KEY_VERSION ?? "1");
  if (!Number.isSafeInteger(activeVersion) || activeVersion < 1) {
    throw new Error("PII_VAULT_ACTIVE_KEY_VERSION must be a positive integer");
  }

  const keys: Keyring = new Map();
  const serialized = env.PII_VAULT_KEYRING;
  if (serialized) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(serialized);
    } catch {
      throw new Error("PII_VAULT_KEYRING must be valid JSON");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("PII_VAULT_KEYRING must be a JSON object");
    }
    for (const [versionText, encoded] of Object.entries(parsed)) {
      const version = Number(versionText);
      if (!Number.isSafeInteger(version) || version < 1 || typeof encoded !== "string") {
        throw new Error("PII_VAULT_KEYRING contains an invalid entry");
      }
      keys.set(version, decodeKey(encoded, version));
    }
  } else if (env.PII_VAULT_MASTER_KEY) {
    keys.set(activeVersion, decodeKey(env.PII_VAULT_MASTER_KEY, activeVersion));
  }

  if (!keys.has(activeVersion)) {
    throw new Error("The active PII vault key is not configured");
  }
  return { activeVersion, keys };
}

export function getActiveVaultKeyVersion(keyring: VaultKeyring = loadKeyring()): number {
  return keyring.activeVersion;
}

// Bound into every ciphertext's associated data. Change it per deployment if
// several services share a keyring, so a record sealed for one cannot be
// replayed into another. The Go package uses the same constant.
export const VAULT_SERVICE = "pii-vault";

// HKDF info prefix; also shared with the Go package.
export const VAULT_HKDF_LABEL = "pii-vault";

export function canonicalContext(context: EncryptionContext): Buffer {
  return Buffer.from(
    JSON.stringify({
      service: VAULT_SERVICE,
      purpose: "pii-vault",
      tenantId: context.tenantId,
      vaultId: context.vaultId,
      ownerType: context.ownerType,
      ownerId: context.ownerId,
      type: context.type,
      keyVersion: context.keyVersion,
    }),
    "utf8",
  );
}

function deriveRecordKey(context: EncryptionContext, keyring: VaultKeyring): Buffer {
  const { keys } = keyring;
  const masterKey = keys.get(context.keyVersion);
  if (!masterKey) {
    throw new Error(`PII vault key version ${context.keyVersion} is unavailable`);
  }

  return Buffer.from(
    hkdfSync(
      "sha256",
      masterKey,
      Buffer.from(`tenant:${context.tenantId}`, "utf8"),
      Buffer.from(
        `${VAULT_HKDF_LABEL}:${context.vaultId}:${context.ownerType}:${context.ownerId}:${context.type}`,
        "utf8",
      ),
      32,
    ),
  );
}

export function validateVaultValue(value: string, type: VaultPiiType): string {
  const normalized = value.trim();
  if (!normalized || Buffer.byteLength(normalized, "utf8") > 4096) {
    throw new Error("Sensitive value is empty or too large");
  }

  const digits = normalized.replace(/\D/g, "");
  switch (type) {
    case "ssn":
      if (
        digits.length !== 9 ||
        digits.startsWith("000") ||
        digits.slice(3, 5) === "00" ||
        digits.endsWith("0000")
      ) {
        throw new Error("Invalid SSN format");
      }
      break;
    case "drivers_license":
      if (!/^[A-Za-z0-9 -]{4,32}$/.test(normalized)) {
        throw new Error("Invalid driver's license format");
      }
      break;
    case "date_of_birth": {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(normalized)) {
        throw new Error("Date of birth must use YYYY-MM-DD");
      }
      const parsed = new Date(`${normalized}T00:00:00.000Z`);
      if (Number.isNaN(parsed.valueOf()) || parsed >= new Date()) {
        throw new Error("Invalid date of birth");
      }
      break;
    }
    case "credit_score":
    case "co_buyer_score": {
      const score = Number(normalized);
      if (!/^\d{3}$/.test(normalized) || score < 300 || score > 850) {
        throw new Error("Invalid credit score");
      }
      break;
    }
    case "monthly_income":
    case "housing_payment":
    case "preapproval_max":
    case "trade_payoff": {
      if (!/^\d+(?:\.\d{1,2})?$/.test(normalized)) {
        throw new Error("Invalid monetary value");
      }
      const amount = Number(normalized);
      if (!Number.isFinite(amount) || amount < 0 || amount > 100_000_000) {
        throw new Error("Monetary value is outside the allowed range");
      }
      break;
    }
    case "co_buyer_name":
      if (normalized.length > 200 || /[\u0000-\u001F\u007F]/.test(normalized)) {
        throw new Error("Invalid co-buyer name");
      }
      break;
    case "bank_account":
      if (!/^[A-Za-z0-9 -]{4,34}$/.test(normalized)) {
        throw new Error("Invalid bank account format");
      }
      break;
    case "tax_id":
      if (digits.length !== 9) {
        throw new Error("Invalid tax ID format");
      }
      break;
    case "passport":
      if (!/^[A-Za-z0-9 -]{5,20}$/.test(normalized)) {
        throw new Error("Invalid passport format");
      }
      break;
    case "custom":
      break;
  }

  return normalized;
}

export function maskVaultValue(value: string, type: VaultPiiType): string {
  const normalized = value.trim();
  const digits = normalized.replace(/\D/g, "");
  switch (type) {
    case "ssn":
      return `***-**-${digits.slice(-4)}`;
    case "date_of_birth":
      return `****-**-${normalized.slice(-2)}`;
    case "credit_score":
    case "co_buyer_score":
      return "***";
    case "monthly_income":
    case "housing_payment":
    case "preapproval_max":
    case "trade_payoff":
    case "co_buyer_name":
      return "••••";
    case "bank_account":
      return `••••${normalized.replace(/\s/g, "").slice(-4)}`;
    case "drivers_license":
    case "passport":
    case "tax_id":
      return `••••${normalized.replace(/\s/g, "").slice(-4)}`;
    case "custom":
      return "••••";
  }
}

export function encryptVaultValue(
  plaintext: string,
  context: EncryptionContext,
  keyring: VaultKeyring = loadKeyring(),
): EncryptedVaultValue {
  return encryptVaultValueWithIv(plaintext, context, randomBytes(12), keyring);
}

/**
 * The deterministic core of encryptVaultValue. Exported only so the shared
 * test vectors can prove Node and Go produce identical bytes for the same
 * key, IV and context. Never reuse an IV under the same record key in
 * production: call encryptVaultValue.
 */
export function encryptVaultValueWithIv(
  plaintext: string,
  context: EncryptionContext,
  iv: Buffer,
  keyring: VaultKeyring = loadKeyring(),
): EncryptedVaultValue {
  if (iv.length !== 12) {
    throw new Error("PII vault IV must be 12 bytes");
  }
  const normalized = validateVaultValue(plaintext, context.type);
  const cipher = createCipheriv("aes-256-gcm", deriveRecordKey(context, keyring), iv, {
    authTagLength: 16,
  });
  cipher.setAAD(canonicalContext(context));
  const ciphertext = Buffer.concat([
    cipher.update(normalized, "utf8"),
    cipher.final(),
  ]);

  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    algorithm: "aes-256-gcm",
    keyVersion: context.keyVersion,
    displayHint: maskVaultValue(normalized, context.type),
  };
}

export function decryptVaultValue(
  encrypted: Omit<EncryptedVaultValue, "displayHint">,
  context: EncryptionContext,
  keyring: VaultKeyring = loadKeyring(),
): string {
  if (encrypted.algorithm !== "aes-256-gcm") {
    throw new Error("Unsupported PII vault encryption algorithm");
  }
  if (encrypted.keyVersion !== context.keyVersion) {
    throw new Error("PII vault key metadata mismatch");
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    deriveRecordKey(context, keyring),
    Buffer.from(encrypted.iv, "base64"),
    { authTagLength: 16 },
  );
  decipher.setAAD(canonicalContext(context));
  decipher.setAuthTag(Buffer.from(encrypted.authTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}
