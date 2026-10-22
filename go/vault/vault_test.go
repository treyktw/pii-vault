package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testKeys(t *testing.T) Keyring {
	t.Helper()
	k, err := ParseKeyring(`{"1":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) +
		`","2":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)) + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var vectorContext = Context{
	TenantID: "tenant_acme_0001", VaultID: "0b5c8a52-1f7e-4c1e-9a52-3f5d2a7c9e10",
	OwnerType: "client", OwnerID: "client_0001", Type: "ssn", KeyVersion: 2,
}

func loadVectors(t *testing.T) VectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f VectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.NodeSealed) == 0 || len(f.GoSealed) != len(f.NodeSealed) {
		t.Fatalf("vectors.json is incomplete (%d node, %d go); run scripts/generate-vectors.sh",
			len(f.NodeSealed), len(f.GoSealed))
	}
	return f
}

// The test keyring above is the same one the vectors are sealed under.
func TestVectorKeyringMatchesTestKeys(t *testing.T) {
	keys, err := loadVectors(t).ParsedKeyring()
	if err != nil {
		t.Fatal(err)
	}
	want := testKeys(t)
	for v, k := range want {
		if !bytes.Equal(keys[v], k) {
			t.Fatalf("key version %d differs", v)
		}
	}
}

// Sealed by ts/src/vaultCrypto.ts encryptVaultValue with the same keyring and
// context: the Go reader must open what Node wrote.
func TestOpensWhatNodeSealed(t *testing.T) {
	f := loadVectors(t)
	keys, err := f.ParsedKeyring()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f.NodeSealed {
		got, err := keys.Open(v.Sealed(), v.Context.Context())
		if err != nil || got != v.Plaintext {
			t.Errorf("%s: Open = %q, %v", v.Name, got, err)
		}
	}
}

// Same key, IV and context must give the same bytes in both languages, and
// each intermediate (AAD, HKDF output) must match so a regression names the
// step that diverged.
func TestReproducesNodeBytes(t *testing.T) {
	f := loadVectors(t)
	if f.Service != Service || f.HKDFLabel != HKDFLabel {
		t.Fatalf("vectors use service %q / label %q, package uses %q / %q", f.Service, f.HKDFLabel, Service, HKDFLabel)
	}
	keys, err := f.ParsedKeyring()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f.NodeSealed {
		c := v.Context.Context()
		if got := string(c.aad()); got != v.AAD {
			t.Errorf("%s: aad\n got %s\nwant %s", v.Name, got, v.AAD)
			continue
		}
		key, err := keys.recordKey(c)
		if err != nil || hex.EncodeToString(key) != v.RecordKeyHex {
			t.Errorf("%s: record key = %x, %v", v.Name, key, err)
			continue
		}
		iv, err := decodeIV(v.IV)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := keys.sealWithIV(v.Plaintext, c, iv)
		if err != nil {
			t.Fatal(err)
		}
		if sealed != v.Sealed() {
			t.Errorf("%s: Go sealed %+v, Node sealed %+v", v.Name, sealed, v.Sealed())
		}
	}
}

// The committed Go half is what this code produces today.
func TestGoVectorsAreCurrent(t *testing.T) {
	f := loadVectors(t)
	regenerated, err := GenerateGoVectors(f)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range regenerated {
		if v.Sealed() != f.GoSealed[i].Sealed() {
			t.Errorf("%s: goSealed is stale; run scripts/generate-vectors.sh", v.Name)
		}
	}
}

// Rotation: records sealed under an older key version stay readable as long
// as that version is in the keyring, and stop opening once it is retired.
func TestRotationKeepsOldVersionsReadable(t *testing.T) {
	f := loadVectors(t)
	keys, err := f.ParsedKeyring()
	if err != nil {
		t.Fatal(err)
	}
	var v1 *Vector
	for i := range f.NodeSealed {
		if f.NodeSealed[i].Context.KeyVersion == 1 {
			v1 = &f.NodeSealed[i]
			break
		}
	}
	if v1 == nil {
		t.Fatal("no key-version-1 vector")
	}
	if got, err := keys.Open(v1.Sealed(), v1.Context.Context()); err != nil || got != v1.Plaintext {
		t.Fatalf("v1 record under v1+v2 keyring = %q, %v", got, err)
	}
	retired := Keyring{2: keys[2]}
	if _, err := retired.Open(v1.Sealed(), v1.Context.Context()); err == nil {
		t.Fatal("v1 record opened after key version 1 was retired")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	keys := testKeys(t)
	sealed, err := keys.Seal("123-45-6789", vectorContext)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	ct[0] ^= 0x01
	sealed.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	if _, err := keys.Open(sealed, vectorContext); err == nil {
		t.Fatal("opened a tampered ciphertext")
	}
}

func TestContextIsBoundIntoTheCiphertext(t *testing.T) {
	keys := testKeys(t)
	sealed, err := keys.Seal("123-45-6789", vectorContext)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Context){
		"tenant":  func(c *Context) { c.TenantID = "other" },
		"owner":   func(c *Context) { c.OwnerID = "other" },
		"type":    func(c *Context) { c.Type = "tax_id" },
		"vault":   func(c *Context) { c.VaultID = "other" },
		"version": func(c *Context) { c.KeyVersion = 1 },
	} {
		c := vectorContext
		mutate(&c)
		if _, err := keys.Open(sealed, c); err == nil {
			t.Errorf("opened under a different %s", name)
		}
	}
	if got, err := keys.Open(sealed, vectorContext); err != nil || got != "123-45-6789" {
		t.Fatalf("round trip = %q, %v", got, err)
	}
}

func TestKeyringRejectsBadKeys(t *testing.T) {
	for _, raw := range []string{`[]`, `{}`, `{"0":"AAAA"}`, `{"1":"c2hvcnQ="}`, `not json`} {
		if _, err := ParseKeyring(raw); err == nil {
			t.Errorf("ParseKeyring(%s) accepted", raw)
		}
	}
}

func TestKeyringAcceptsWhatNodeAccepts(t *testing.T) {
	key := bytes.Repeat([]byte{0xfb}, 32)
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(key),
		base64.RawStdEncoding.EncodeToString(key),
		base64.RawURLEncoding.EncodeToString(key),
	} {
		k, err := ParseKeyring(`{"1":"` + enc + `"}`)
		if err != nil || !bytes.Equal(k[1], key) {
			t.Errorf("ParseKeyring(%q) = %v", enc, err)
		}
	}
}
