// Command vault-read reads an owner's vault fields with the Go reader and
// prints them as JSON. It exists for the demo and the cross-language
// integration test: the Node library writes, this reads the same rows.
//
//	PII_VAULT_DATABASE_URL=... PII_VAULT_KEYRING=... \
//	  go run ./cmd/vault-read -tenant tenant_a -owner client_0001 -types ssn,date_of_birth
//
// It prints plaintext to stdout, so use it with synthetic data only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/treyktw/pii-vault/go/vault"
)

func main() {
	tenant := flag.String("tenant", "", "tenant id")
	ownerType := flag.String("owner-type", "client", "owner type")
	owner := flag.String("owner", "", "owner id")
	types := flag.String("types", "ssn", "comma-separated field types")
	actorID := flag.String("actor", "go-reader", "actor user id written to the access log")
	actorRole := flag.String("role", "manager", "actor role written to the access log")
	reason := flag.String("reason", "Read from the Go reader for the demo", "access reason (10-500 chars)")
	flag.Parse()
	if *tenant == "" || *owner == "" {
		fmt.Fprintln(os.Stderr, "vault-read: -tenant and -owner are required")
		os.Exit(2)
	}

	keys, err := vault.ParseKeyring(os.Getenv("PII_VAULT_KEYRING"))
	if err != nil {
		fail(err)
	}
	ctx := context.Background()
	reader, err := vault.Open(ctx, os.Getenv("PII_VAULT_DATABASE_URL"), keys)
	if err != nil {
		fail(err)
	}
	defer reader.Close()

	values, err := reader.Read(ctx, vault.Actor{UserID: *actorID, Role: *actorRole},
		*tenant, *ownerType, *owner, strings.Split(*types, ","), *reason)
	if err != nil {
		fail(err)
	}
	out, _ := json.Marshal(values)
	fmt.Println(string(out))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "vault-read:", err)
	os.Exit(1)
}
