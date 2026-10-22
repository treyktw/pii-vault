// Cross-language interop: testdata/vectors.json holds records sealed by Node
// (nodeSealed) and by Go (goSealed) under the same public test keyring. Node
// must open what Go wrote, and reproduce its own half byte for byte. The Go
// suite (go/vault/vault_test.go) checks the mirror image.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  VAULT_HKDF_LABEL,
  VAULT_SERVICE,
  canonicalContext,
  decryptVaultValue,
  encryptVaultValueWithIv,
  loadKeyring,
  type EncryptionContext,
} from "../src/vaultCrypto.js";

type Vector = {
  name: string;
  context: EncryptionContext;
  plaintext: string;
  aad?: string;
  iv: string;
  ciphertext: string;
  authTag: string;
  algorithm: "aes-256-gcm";
  displayHint?: string;
};

type VectorFile = {
  service: string;
  hkdfLabel: string;
  keyring: Record<string, string>;
  nodeSealed: Vector[];
  goSealed: Vector[];
};

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(here, "..", "..", "testdata", "vectors.json"), "utf8"),
) as VectorFile;

const keyring = loadKeyring({
  PII_VAULT_KEYRING: JSON.stringify(vectors.keyring),
  PII_VAULT_ACTIVE_KEY_VERSION: "2",
});

describe("shared test vectors", () => {
  it("are complete and use this build's constants", () => {
    expect(vectors.nodeSealed.length).toBeGreaterThan(0);
    expect(vectors.goSealed).toHaveLength(vectors.nodeSealed.length);
    expect(vectors.service).toBe(VAULT_SERVICE);
    expect(vectors.hkdfLabel).toBe(VAULT_HKDF_LABEL);
  });

  it.each(vectors.goSealed.map((vector) => [vector.name, vector] as const))(
    "Node opens what Go sealed: %s",
    (_name, vector) => {
      const opened = decryptVaultValue(
        { ...vector, keyVersion: vector.context.keyVersion },
        vector.context,
        keyring,
      );
      expect(opened).toBe(vector.plaintext);
    },
  );

  it.each(vectors.nodeSealed.map((vector) => [vector.name, vector] as const))(
    "Node reproduces its committed bytes: %s",
    (_name, vector) => {
      expect(canonicalContext(vector.context).toString("utf8")).toBe(vector.aad);
      const resealed = encryptVaultValueWithIv(
        vector.plaintext,
        vector.context,
        Buffer.from(vector.iv, "base64"),
        keyring,
      );
      expect(resealed.ciphertext).toBe(vector.ciphertext);
      expect(resealed.authTag).toBe(vector.authTag);
      expect(resealed.displayHint).toBe(vector.displayHint);
    },
  );

  it("Go and Node seal the same plaintexts under the same contexts", () => {
    for (const [index, goVector] of vectors.goSealed.entries()) {
      const nodeVector = vectors.nodeSealed[index]!;
      expect(goVector.context).toEqual(nodeVector.context);
      expect(goVector.plaintext).toBe(nodeVector.plaintext);
      // Different IVs, so different ciphertexts: neither side copied the other.
      expect(goVector.iv).not.toBe(nodeVector.iv);
    }
  });
});
