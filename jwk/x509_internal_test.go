package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestPublicMaterialReducesEveryPrivateKeyType(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an ECDSA key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate an RSA key: %v", err)
	}

	ed25519PublicKey, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an Ed25519 key: %v", err)
	}

	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an X25519 key: %v", err)
	}

	for _, test := range []struct {
		name     string
		material any
		want     crypto.PublicKey
	}{
		{"ECDSAPrivate", ecdsaKey, &ecdsaKey.PublicKey},
		{"RSAPrivate", rsaKey, &rsaKey.PublicKey},
		{"Ed25519Private", ed25519Key, ed25519PublicKey},
		{"X25519Private", x25519Key, x25519Key.PublicKey()},
		{"ECDSAPublic", &ecdsaKey.PublicKey, &ecdsaKey.PublicKey},
		{"RSAPublic", &rsaKey.PublicKey, &rsaKey.PublicKey},
		{"Ed25519Public", ed25519PublicKey, ed25519PublicKey},
		{"X25519Public", x25519Key.PublicKey(), x25519Key.PublicKey()},
	} {
		t.Run(test.name, func(t *testing.T) {
			material, ok := publicMaterial(test.material)
			if !ok {
				t.Fatalf("publicMaterial refused a %T", test.material)
			}

			if !material.Equal(test.want) {
				t.Errorf("publicMaterial gives %T, which is not the public half of a %T",
					material, test.material)
			}
		})
	}
}

func TestPublicMaterialRefusesMaterialWithNoPublicHalf(t *testing.T) {
	for _, test := range []struct {
		name     string
		material any
	}{
		{"Symmetric", []byte("a symmetric key")},
		{"None", nil},
		{"NotAKey", "a string"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if material, ok := publicMaterial(test.material); ok {
				t.Errorf("publicMaterial gives %v for a %T, want no result", material, test.material)
			}
		})
	}
}
