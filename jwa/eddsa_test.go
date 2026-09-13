package jwa_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
)

const (
	ed25519Seed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	ed25519PublicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

func decodeEd25519PublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()

	publicKey, err := base64.RawURLEncoding.DecodeString(ed25519PublicKey)
	if err != nil {
		t.Fatalf("cannot decode public key: %v", err)
	}

	return ed25519.PublicKey(publicKey)
}

func TestEdDSARejectsWrongKeyType(t *testing.T) {
	secret := []byte(ed25519Seed)

	if _, err := jwa.EdDSA().Sign([]byte("token"), secret); !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Errorf("signing with []byte: got error %v, want %v", err, jwa.ErrInvalidKeyType)
	}

	if err := jwa.EdDSA().Verify([]byte("token"), []byte("signature"), secret); !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Errorf("verifying with []byte: got error %v, want %v", err, jwa.ErrInvalidKeyType)
	}
}

func TestEdDSARejectsMisSizedKey(t *testing.T) {
	t.Run("Signing", func(t *testing.T) {
		if _, err := jwa.EdDSA().Sign([]byte("token"), ed25519.PrivateKey("short")); !errors.Is(err, jwa.ErrInvalidKeyType) {
			t.Errorf("got error %v, want %v", err, jwa.ErrInvalidKeyType)
		}
	})

	t.Run("Verifying", func(t *testing.T) {
		signature := make([]byte, ed25519.SignatureSize)

		if err := jwa.EdDSA().Verify([]byte("token"), signature, ed25519.PublicKey("short")); !errors.Is(err, jwa.ErrInvalidKeyType) {
			t.Errorf("got error %v, want %v", err, jwa.ErrInvalidKeyType)
		}
	})
}

func TestEdDSARejectsMalformedSignature(t *testing.T) {
	err := jwa.EdDSA().Verify([]byte("token"), []byte("short"), decodeEd25519PublicKey(t))

	if !errors.Is(err, jwa.ErrMalformedSignature) {
		t.Errorf("got error %v, want %v", err, jwa.ErrMalformedSignature)
	}
}

func TestEdDSARejectsWrongSignature(t *testing.T) {
	signature := make([]byte, ed25519.SignatureSize)

	err := jwa.EdDSA().Verify([]byte("token"), signature, decodeEd25519PublicKey(t))

	if !errors.Is(err, jwa.ErrSignatureMismatch) {
		t.Errorf("got %v, want %v", err, jwa.ErrSignatureMismatch)
	}
}
