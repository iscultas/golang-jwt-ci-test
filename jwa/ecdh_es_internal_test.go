package jwa

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/internal/curve"
)

func TestECDHESSeparatesItsTwoModes(t *testing.T) {
	recipientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	ephemeralAgreementKey, err := ephemeralKey.ECDH()
	if err != nil {
		t.Fatalf("cannot convert the ephemeral key: %v", err)
	}

	recipientAgreementKey, err := recipientKey.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("cannot convert the recipient key: %v", err)
	}

	encryption := A128GCM()

	if ecdhES.derivedKeySize(encryption) != ecdhESA128KW.derivedKeySize(encryption) {
		t.Fatal("the two modes derive different lengths here, so this test proves nothing")
	}

	direct, err := ecdhES.agree(ephemeralAgreementKey, recipientAgreementKey, encryption, new(KeyParameters))
	if err != nil {
		t.Fatalf("cannot agree directly: %v", err)
	}

	wrapping, err := ecdhESA128KW.agree(ephemeralAgreementKey, recipientAgreementKey, encryption, new(KeyParameters))
	if err != nil {
		t.Fatalf("cannot agree with wrapping: %v", err)
	}

	if bytes.Equal(direct, wrapping) {
		t.Error("the two modes derived the same key from the same agreement")
	}

	if got := ecdhES.algorithmID(encryption); got != "A128GCM" {
		t.Errorf("Direct Key Agreement: got AlgorithmID %q, want the enc value %q", got, "A128GCM")
	}

	if got := ecdhESA128KW.algorithmID(encryption); got != "ECDH-ES+A128KW" {
		t.Errorf("Key Agreement with Key Wrapping: got AlgorithmID %q, want the alg value %q", got, "ECDH-ES+A128KW")
	}
}

const (
	appendixA6RecipientPublicKey = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	appendixA6EphemeralSecret    = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	appendixA6EphemeralPublicKey = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	appendixA6SharedSecret       = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

func decodeHex(t *testing.T, encoded string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("cannot decode %q: %v", encoded, err)
	}

	return decoded
}

func TestTheAppendixA6AgreementReachesThePublishedSecret(t *testing.T) {
	ephemeralKey, err := ecdh.X25519().NewPrivateKey(decodeHex(t, appendixA6EphemeralSecret))
	if err != nil {
		t.Fatalf("cannot read the ephemeral secret: %v", err)
	}

	if got := ephemeralKey.PublicKey().Bytes(); !bytes.Equal(got, decodeHex(t, appendixA6EphemeralPublicKey)) {
		t.Fatalf("the ephemeral secret derives %x, want the published %s", got, appendixA6EphemeralPublicKey)
	}

	recipientKey, err := ecdh.X25519().NewPublicKey(decodeHex(t, appendixA6RecipientPublicKey))
	if err != nil {
		t.Fatalf("cannot read the recipient key: %v", err)
	}

	sharedSecret, err := ephemeralKey.ECDH(recipientKey)
	if err != nil {
		t.Fatalf("cannot agree: %v", err)
	}

	if !bytes.Equal(sharedSecret, decodeHex(t, appendixA6SharedSecret)) {
		t.Fatalf("agreed %x, want the published %s", sharedSecret, appendixA6SharedSecret)
	}

	derivedKey, err := ecdhESA128KW.agree(ephemeralKey, recipientKey, A128GCM(), new(KeyParameters))
	if err != nil {
		t.Fatalf("cannot derive: %v", err)
	}

	expectedKey := concatKDF(
		decodeHex(t, appendixA6SharedSecret), "ECDH-ES+A128KW", nil, nil, ecdhESA128KW.derivedKeySize(A128GCM()),
	)

	if !bytes.Equal(derivedKey, expectedKey) {
		t.Errorf("derived %x from the published Z, want %x", derivedKey, expectedKey)
	}
}

func TestAnAgreementAcrossCurveFamiliesIsRefused(t *testing.T) {
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an X25519 key: %v", err)
	}

	nistKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a P-256 key: %v", err)
	}

	for name, pair := range map[string]struct {
		privateKey *ecdh.PrivateKey
		publicKey  *ecdh.PublicKey
	}{
		"X25519 private, P-256 epk": {x25519Key, nistKey.PublicKey()},
		"P-256 private, X25519 epk": {nistKey, x25519Key.PublicKey()},
	} {
		t.Run(name, func(t *testing.T) {
			derivedKey, err := ecdhES.agree(pair.privateKey, pair.publicKey, A128GCM(), new(KeyParameters))
			if !errors.Is(err, ErrInvalidKeyType) {
				t.Fatalf("got error %v, want ErrInvalidKeyType", err)
			}

			if derivedKey != nil {
				t.Errorf("got a derived key %x alongside the error", derivedKey)
			}

			for _, offered := range []ecdh.Curve{pair.privateKey.Curve(), pair.publicKey.Curve()} {
				if !strings.Contains(err.Error(), curve.Name(offered)) {
					t.Errorf("the error %q does not name %s", err, curve.Name(offered))
				}
			}
		})
	}
}

func TestECDHESDerivesTheWrappingKeySize(t *testing.T) {
	for _, pairing := range []struct {
		algorithm *ECDHESAlgorithm
		size      int
	}{
		{ecdhESA128KW, 16},
		{ecdhESA192KW, 24},
		{ecdhESA256KW, 32},
	} {
		t.Run(pairing.algorithm.String(), func(t *testing.T) {
			if got := pairing.algorithm.derivedKeySize(A256CBCHS512()); got != pairing.size {
				t.Errorf("got %d octets, want %d", got, pairing.size)
			}
		})
	}

	for _, encryption := range []ContentEncrypter{A128GCM(), A256GCM(), A256CBCHS512()} {
		if got := ecdhES.derivedKeySize(encryption); got != encryption.KeySize() {
			t.Errorf("%s: got %d octets, want the enc key size %d", encryption, got, encryption.KeySize())
		}
	}
}
