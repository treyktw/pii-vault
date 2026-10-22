package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

// VectorContext is a Context as the shared vectors spell it (the TypeScript
// EncryptionContext field names).
type VectorContext struct {
	TenantID   string `json:"tenantId"`
	VaultID    string `json:"vaultId"`
	OwnerType  string `json:"ownerType"`
	OwnerID    string `json:"ownerId"`
	Type       string `json:"type"`
	KeyVersion int    `json:"keyVersion"`
}

// Context converts to the package's Context.
func (v VectorContext) Context() Context {
	return Context{
		TenantID: v.TenantID, VaultID: v.VaultID, OwnerType: v.OwnerType,
		OwnerID: v.OwnerID, Type: v.Type, KeyVersion: v.KeyVersion,
	}
}

// Vector is one sealed record in testdata/vectors.json.
type Vector struct {
	Name         string        `json:"name"`
	Context      VectorContext `json:"context"`
	Plaintext    string        `json:"plaintext"`
	AAD          string        `json:"aad,omitempty"`
	RecordKeyHex string        `json:"recordKeyHex,omitempty"`
	IV           string        `json:"iv"`
	Ciphertext   string        `json:"ciphertext"`
	AuthTag      string        `json:"authTag"`
	Algorithm    string        `json:"algorithm"`
	DisplayHint  string        `json:"displayHint,omitempty"`
}

// Sealed returns the vector's ciphertext fields.
func (v Vector) Sealed() Sealed {
	return Sealed{Ciphertext: v.Ciphertext, IV: v.IV, AuthTag: v.AuthTag, Algorithm: v.Algorithm}
}

// VectorFile is testdata/vectors.json.
type VectorFile struct {
	Description string            `json:"description"`
	Service     string            `json:"service"`
	HKDFLabel   string            `json:"hkdfLabel"`
	Keyring     map[string]string `json:"keyring"`
	NodeSealed  []Vector          `json:"nodeSealed"`
	GoSealed    []Vector          `json:"goSealed"`
}

// ParsedKeyring parses the file's keyring with ParseKeyring.
func (f VectorFile) ParsedKeyring() (Keyring, error) {
	raw, err := json.Marshal(f.Keyring)
	if err != nil {
		return nil, err
	}
	return ParseKeyring(string(raw))
}

// GenerateGoVectors seals every Node vector's context and plaintext with the
// Go implementation, under deterministic IVs distinct from Node's.
func GenerateGoVectors(f VectorFile) ([]Vector, error) {
	keys, err := f.ParsedKeyring()
	if err != nil {
		return nil, err
	}
	out := make([]Vector, 0, len(f.NodeSealed))
	for i, nv := range f.NodeSealed {
		iv := goVectorIV(i)
		sealed, err := keys.sealWithIV(nv.Plaintext, nv.Context.Context(), iv)
		if err != nil {
			return nil, fmt.Errorf("vector %s: %w", nv.Name, err)
		}
		out = append(out, Vector{
			Name:       nv.Name,
			Context:    nv.Context,
			Plaintext:  nv.Plaintext,
			IV:         sealed.IV,
			Ciphertext: sealed.Ciphertext,
			AuthTag:    sealed.AuthTag,
			Algorithm:  sealed.Algorithm,
		})
	}
	return out, nil
}

func goVectorIV(index int) []byte {
	sum := sha256.Sum256([]byte("go-vector:" + strconv.Itoa(index)))
	return sum[:12]
}

// decodeIV is exposed to tests for the byte-for-byte reproduction check.
func decodeIV(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
