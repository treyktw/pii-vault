// Command gen-vectors adds the Go half of testdata/vectors.json: the same
// contexts as the Node half, sealed by the Go package with its own fixed IVs,
// so the TypeScript tests can prove Node opens what Go wrote.
//
//	go run ./cmd/gen-vectors ../testdata/vectors.json
//
// Run scripts/generate-vectors.sh rather than this directly: it writes the
// Node half first.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/treyktw/pii-vault/go/vault"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-vectors <vectors.json>")
		os.Exit(1)
	}
	path := os.Args[1]
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	var file vault.VectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		fail(err)
	}
	file.GoSealed, err = vault.GenerateGoVectors(file)
	if err != nil {
		fail(err)
	}

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(file); err != nil {
		fail(err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %d Go-sealed vectors to %s\n", len(file.GoSealed), path)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen-vectors:", err)
	os.Exit(1)
}
