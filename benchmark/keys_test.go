package benchmark_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/iscultas/jwt-go/jwk"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

const keyID = "2026-08"

var (
	hmacSecret = mustRead(32)

	contentKey = mustRead(32)

	rsaPrivateKey     = mustGenerateRSA()
	ecdsaPrivateKey   = mustGenerateECDSA()
	ed25519PrivateKey = mustGenerateEd25519()
)

var (
	jwtgoHMACKey    = jwk.NewKey(hmacSecret, jwk.WithID(keyID))
	jwtgoRSAKey     = jwk.NewKey(rsaPrivateKey, jwk.WithID(keyID))
	jwtgoECDSAKey   = jwk.NewKey(ecdsaPrivateKey, jwk.WithID(keyID))
	jwtgoEd25519Key = jwk.NewKey(ed25519PrivateKey, jwk.WithID(keyID))
)

var (
	jwxHMACKey    = mustImport(hmacSecret)
	jwxRSAKey     = mustImport(rsaPrivateKey)
	jwxECDSAKey   = mustImport(ecdsaPrivateKey)
	jwxEd25519Key = mustImport(ed25519PrivateKey)

	jwxRSAPublicKey     = mustImport(&rsaPrivateKey.PublicKey)
	jwxECDSAPublicKey   = mustImport(&ecdsaPrivateKey.PublicKey)
	jwxEd25519PublicKey = mustImport(ed25519PrivateKey.Public().(ed25519.PublicKey))
)

func mustRead(length int) []byte {
	material := make([]byte, length)
	if _, err := rand.Read(material); err != nil {
		panic(err)
	}

	return material
}

func mustGenerateRSA() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return key
}

func mustGenerateECDSA() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return key
}

func mustGenerateEd25519() ed25519.PrivateKey {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return key
}

func mustImport(material any) jwxjwk.Key {
	key, err := jwxjwk.Import(material)
	if err != nil {
		panic(err)
	}

	if err := key.Set(jwxjwk.KeyIDKey, keyID); err != nil {
		panic(err)
	}

	return key
}

func fatal(b testing.TB, err error) {
	b.Helper()

	if err != nil {
		b.Fatalf("benchmark arm failed: %v", err)
	}
}
