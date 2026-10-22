// Writes the Node half of testdata/vectors.json: records sealed by
// encryptVaultValueWithIv with fixed, obviously fake keys and fixed IVs, plus
// the intermediate AAD and record key so a mismatch on the Go side points at
// the exact step that diverged. go/cmd/gen-vectors then adds the Go half.
//
//   npx tsx scripts/generate-vectors.ts ../testdata/vectors.json
//
// Never use these keys for anything real. Fixed IVs are only safe here
// because the keys are public test data.
import { createHash, hkdfSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import {
  VAULT_HKDF_LABEL,
  VAULT_SERVICE,
  canonicalContext,
  encryptVaultValueWithIv,
  loadKeyring,
  type EncryptionContext,
} from "../src/vaultCrypto.js";

const outputPath = process.argv[2];
if (!outputPath) {
  console.error("usage: generate-vectors.ts <output.json>");
  process.exit(1);
}

// 0x07 * 32 and 0x09 * 32: test keys only.
const keyringJson = {
  "1": Buffer.alloc(32, 0x07).toString("base64"),
  "2": Buffer.alloc(32, 0x09).toString("base64"),
};
const keyring = loadKeyring({
  PII_VAULT_KEYRING: JSON.stringify(keyringJson),
  PII_VAULT_ACTIVE_KEY_VERSION: "2",
});

type VectorCase = {
  name: string;
  context: EncryptionContext;
  plaintext: string;
};

const cases: VectorCase[] = [
  {
    name: "ssn-v2",
    context: {
      tenantId: "tenant_acme_0001",
      vaultId: "0b5c8a52-1f7e-4c1e-9a52-3f5d2a7c9e10",
      ownerType: "client",
      ownerId: "client_0001",
      type: "ssn",
      keyVersion: 2,
    },
    plaintext: "123-45-6789",
  },
  {
    name: "ssn-v1-rotated-key",
    context: {
      tenantId: "tenant_acme_0001",
      vaultId: "6f1c2e44-9b0a-4f3d-8e21-5a7b9c0d1e2f",
      ownerType: "client",
      ownerId: "client_0002",
      type: "ssn",
      keyVersion: 1,
    },
    plaintext: "987-65-4320",
  },
  {
    name: "date-of-birth",
    context: {
      tenantId: "tenant_globex_0002",
      vaultId: "a3d4e5f6-0718-4293-a4b5-c6d7e8f90a1b",
      ownerType: "user",
      ownerId: "user_42",
      type: "date_of_birth",
      keyVersion: 2,
    },
    plaintext: "1990-01-31",
  },
  {
    name: "unicode-co-buyer-name",
    context: {
      tenantId: "tenant_globex_0002",
      vaultId: "b4e5f607-1829-43a4-b5c6-d7e8f90a1b2c",
      ownerType: "deal",
      ownerId: "deal_ünïcødé_😀",
      type: "co_buyer_name",
      keyVersion: 2,
    },
    plaintext: "Zoë Example-Testperson 😀",
  },
  {
    // JSON.stringify writes U+2028/U+2029 literally; Go's encoder escapes
    // them. The Go AAD builder undoes that, and this case proves it.
    name: "line-separator-in-owner-id",
    context: {
      tenantId: "tenant_acme_0001",
      vaultId: "c5f60718-293a-44b5-c6d7-e8f90a1b2c3d",
      ownerType: "organization",
      ownerId: "org with separators<&>\"quoted\"",
      type: "custom",
      keyVersion: 1,
    },
    plaintext: "free-form restricted note",
  },
  {
    name: "monthly-income",
    context: {
      tenantId: "tenant_acme_0001",
      vaultId: "d6071829-3a4b-45c6-d7e8-f90a1b2c3d4e",
      ownerType: "client",
      ownerId: "client_0001",
      type: "monthly_income",
      keyVersion: 2,
    },
    plaintext: "8250.00",
  },
];

function fixedIv(index: number): Buffer {
  return createHash("sha256").update(`node-vector:${index}`).digest().subarray(0, 12);
}

const nodeSealed = cases.map((vectorCase, index) => {
  const iv = fixedIv(index);
  const sealed = encryptVaultValueWithIv(vectorCase.plaintext, vectorCase.context, iv, keyring);
  const masterKey = keyring.keys.get(vectorCase.context.keyVersion)!;
  const recordKey = Buffer.from(
    hkdfSync(
      "sha256",
      masterKey,
      Buffer.from(`tenant:${vectorCase.context.tenantId}`, "utf8"),
      Buffer.from(
        `${VAULT_HKDF_LABEL}:${vectorCase.context.vaultId}:${vectorCase.context.ownerType}:${vectorCase.context.ownerId}:${vectorCase.context.type}`,
        "utf8",
      ),
      32,
    ),
  );
  return {
    name: vectorCase.name,
    context: vectorCase.context,
    plaintext: vectorCase.plaintext,
    aad: canonicalContext(vectorCase.context).toString("utf8"),
    recordKeyHex: recordKey.toString("hex"),
    iv: sealed.iv,
    ciphertext: sealed.ciphertext,
    authTag: sealed.authTag,
    algorithm: sealed.algorithm,
    displayHint: sealed.displayHint,
  };
});

const vectors = {
  description:
    "Shared Node/Go test vectors for pii-vault. Keys are public test data. Regenerate with scripts/generate-vectors.sh.",
  service: VAULT_SERVICE,
  hkdfLabel: VAULT_HKDF_LABEL,
  keyring: keyringJson,
  nodeSealed,
  goSealed: [] as unknown[],
};

writeFileSync(outputPath, `${JSON.stringify(vectors, null, 2)}\n`);
console.log(`wrote ${nodeSealed.length} Node-sealed vectors to ${outputPath}`);
