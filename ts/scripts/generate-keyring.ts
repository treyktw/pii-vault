// Prints a fresh keyring for PII_VAULT_KEYRING.
//
//   npx tsx scripts/generate-keyring.ts            # new keyring, version 1
//   npx tsx scripts/generate-keyring.ts --rotate   # add a version to $PII_VAULT_KEYRING
//
// Output goes to stdout only. Put it in your secret manager, not in a file
// in this repository.
import { randomBytes } from "node:crypto";
import { loadKeyring } from "../src/vaultCrypto.js";

const rotate = process.argv.includes("--rotate");

let entries: Record<string, string> = {};
if (rotate) {
  const current = process.env.PII_VAULT_KEYRING;
  if (!current) {
    console.error("--rotate needs the current PII_VAULT_KEYRING in the environment");
    process.exit(1);
  }
  // Validates the existing keyring before extending it.
  const existing = loadKeyring({
    PII_VAULT_KEYRING: current,
    PII_VAULT_ACTIVE_KEY_VERSION: process.env.PII_VAULT_ACTIVE_KEY_VERSION ?? "1",
  });
  entries = JSON.parse(current) as Record<string, string>;
  void existing;
}

const nextVersion = Math.max(0, ...Object.keys(entries).map(Number)) + 1;
entries[String(nextVersion)] = randomBytes(32).toString("base64");

console.log(`PII_VAULT_KEYRING='${JSON.stringify(entries)}'`);
console.log(`PII_VAULT_ACTIVE_KEY_VERSION=${nextVersion}`);
if (rotate) {
  console.error(
    `Added key version ${nextVersion}. Deploy it to every reader before switching writers to it, ` +
      "then re-seal old records before removing older versions.",
  );
}
