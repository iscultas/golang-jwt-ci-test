package benchmark_test

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

const setSize = 4

var jwkDocument = func() []byte {
	document, err := json.Marshal(jwtgoECDSAKey.Public())
	if err != nil {
		panic(err)
	}

	return document
}()

var (
	lookupID = fmt.Sprintf("key-%d", setSize-1)

	jwtgoLookupSet = func() *jwk.KeySet {
		keys := make([]*jwk.Key, setSize)

		for index := range keys {
			_, material, err := ed25519.GenerateKey(nil)
			if err != nil {
				panic(err)
			}

			keys[index] = jwk.NewKey(
				material.Public(),
				jwk.WithID(fmt.Sprintf("key-%d", index)),
				jwk.WithPublicKeyUse(jwk.Signature),
				jwk.WithOperations(jwk.Verify),
			)
		}

		return jwk.NewKeySet(keys...)
	}()

	jwxLookupSet = func() jwxjwk.Set {
		set := jwxjwk.NewSet()

		for index := range setSize {
			_, material, err := ed25519.GenerateKey(nil)
			if err != nil {
				panic(err)
			}

			key, err := jwxjwk.Import(material.Public().(ed25519.PublicKey))
			if err != nil {
				panic(err)
			}

			if err := key.Set(jwxjwk.KeyIDKey, fmt.Sprintf("key-%d", index)); err != nil {
				panic(err)
			}

			if err := set.AddKey(key); err != nil {
				panic(err)
			}
		}

		return set
	}()
)

func BenchmarkJWKParse(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			fatal(b, json.Unmarshal(jwkDocument, new(jwk.Key)))
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			_, err := jwxjwk.ParseKey(jwkDocument)
			fatal(b, err)
		}
	})
}

func BenchmarkJWKMarshal(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		key := jwtgoECDSAKey.Public()

		b.ReportAllocs()

		for b.Loop() {
			_, err := json.Marshal(key)
			fatal(b, err)
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			_, err := json.Marshal(jwxECDSAPublicKey)
			fatal(b, err)
		}
	})
}

func BenchmarkJWKThumbprint(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		key := jwtgoECDSAKey.Public()

		b.ReportAllocs()

		for b.Loop() {
			_, err := key.Thumbprint(crypto.SHA256)
			fatal(b, err)
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			_, err := jwxECDSAPublicKey.Thumbprint(crypto.SHA256)
			fatal(b, err)
		}
	})
}

func BenchmarkJWKSetLookup(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		operations := []jwk.Operation{jwk.Verify}

		b.ReportAllocs()

		for b.Loop() {
			_, err := jwtgoLookupSet.Key(jwk.Signature, operations, jwa.EdDSA(), lookupID)
			fatal(b, err)
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			if _, found := jwxLookupSet.LookupKeyID(lookupID); !found {
				b.Fatal("benchmark arm failed: no key with that identifier")
			}
		}
	})
}
