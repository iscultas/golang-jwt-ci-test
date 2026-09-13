package jwa_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
	"testing"

	"github.com/iscultas/jwt-go/internal/curve"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

const (
	appendixCEphemeralKey = `{"kty":"EC",
		"crv":"P-256",
		"x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
		"y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
		"d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}`

	appendixCRecipientKey = `{"kty":"EC",
		"crv":"P-256",
		"x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
		"y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
		"d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}`

	appendixCDerivedKey = "VqqN6vgjbSBcIijNcacQGg"
)

func parseECKey(t *testing.T, encoded string) *ecdsa.PrivateKey {
	t.Helper()

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(encoded), key); err != nil {
		t.Fatalf("cannot parse the key: %v", err)
	}

	privateKey, ok := key.Material().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PrivateKey", key.Material())
	}

	return privateKey
}

func TestECDHESReproducesAppendixC(t *testing.T) {
	ephemeralKey := parseECKey(t, appendixCEphemeralKey)
	recipientKey := parseECKey(t, appendixCRecipientKey)

	cek, err := jwa.ECDHES().DecryptKey(
		[]byte{},
		recipientKey,
		jwa.A128GCM(),
		&jwa.KeyParameters{
			EphemeralPublicKey:  &ephemeralKey.PublicKey,
			AgreementPartyUInfo: []byte("Alice"),
			AgreementPartyVInfo: []byte("Bob"),
		},
	)
	if err != nil {
		t.Fatalf("cannot agree the key: %v", err)
	}

	want, err := base64.RawURLEncoding.DecodeString(appendixCDerivedKey)
	if err != nil {
		t.Fatalf("cannot decode the expected key: %v", err)
	}

	if !bytes.Equal(cek, want) {
		t.Errorf("CEK mismatch:\n got %x\nwant %x", cek, want)
	}
}

func TestECDHESAgreesFromEitherSide(t *testing.T) {
	ephemeralKey := parseECKey(t, appendixCEphemeralKey)
	recipientKey := parseECKey(t, appendixCRecipientKey)

	parameters := func(publicKey *ecdsa.PublicKey) *jwa.KeyParameters {
		return &jwa.KeyParameters{
			EphemeralPublicKey:  publicKey,
			AgreementPartyUInfo: []byte("Alice"),
			AgreementPartyVInfo: []byte("Bob"),
		}
	}

	fromBob, err := jwa.ECDHES().DecryptKey(
		[]byte{}, recipientKey, jwa.A128GCM(), parameters(&ephemeralKey.PublicKey),
	)
	if err != nil {
		t.Fatalf("cannot agree from Bob's side: %v", err)
	}

	fromAlice, err := jwa.ECDHES().DecryptKey(
		[]byte{}, ephemeralKey, jwa.A128GCM(), parameters(&recipientKey.PublicKey),
	)
	if err != nil {
		t.Fatalf("cannot agree from Alice's side: %v", err)
	}

	if !bytes.Equal(fromAlice, fromBob) {
		t.Errorf("the two sides disagreed:\n%x\n%x", fromAlice, fromBob)
	}
}

func TestECDHESGeneratesAFreshEphemeralKey(t *testing.T) {
	recipientKey := parseECKey(t, appendixCRecipientKey)

	first := new(jwa.KeyParameters)
	firstCEK, _, err := jwa.ECDHES().EncryptKey(&recipientKey.PublicKey, jwa.A128GCM(), first)
	if err != nil {
		t.Fatalf("cannot encrypt the key: %v", err)
	}

	second := new(jwa.KeyParameters)
	secondCEK, _, err := jwa.ECDHES().EncryptKey(&recipientKey.PublicKey, jwa.A128GCM(), second)
	if err != nil {
		t.Fatalf("cannot encrypt the key again: %v", err)
	}

	if first.EphemeralPublicKey.(*ecdsa.PublicKey).Equal(second.EphemeralPublicKey.(*ecdsa.PublicKey)) {
		t.Error("two operations shared an ephemeral key")
	}

	if bytes.Equal(firstCEK, secondCEK) {
		t.Error("two operations derived the same CEK")
	}
}

func TestECDHESRejectsAnEphemeralKeyOnAnotherCurve(t *testing.T) {
	recipientKey := parseECKey(t, appendixCRecipientKey)

	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			otherCurveKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("cannot generate a key: %v", err)
			}

			if _, err := jwa.ECDHES().DecryptKey(
				[]byte{},
				recipientKey,
				jwa.A128GCM(),
				&jwa.KeyParameters{EphemeralPublicKey: &otherCurveKey.PublicKey},
			); !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("got %v, want ErrInvalidKeyType", err)
			}
		})
	}
}

func TestECDHESRejectsAPointOffTheCurve(t *testing.T) {
	recipientKey := parseECKey(t, appendixCRecipientKey)
	ephemeralKey := parseECKey(t, appendixCEphemeralKey)

	offCurve := &ecdsa.PublicKey{
		Curve: ephemeralKey.Curve,
		//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
		X: new(big.Int).Add(ephemeralKey.X, big.NewInt(1)),
		//nolint:staticcheck // Raw coordinates make an invalid key, which is the input under test.
		Y: ephemeralKey.Y,
	}

	if _, err := jwa.ECDHES().DecryptKey(
		[]byte{}, recipientKey, jwa.A128GCM(), &jwa.KeyParameters{EphemeralPublicKey: offCurve},
	); !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Errorf("got %v, want ErrInvalidKeyType", err)
	}
}

func TestTheEphemeralKeyThatEncryptPublishesIsTheOneItAgreedWith(t *testing.T) {
	recipientKey := parseECKey(t, appendixCRecipientKey)

	parameters := new(jwa.KeyParameters)

	contentEncryptionKey, _, err := jwa.ECDHES().EncryptKey(
		&recipientKey.PublicKey, jwa.A128GCM(), parameters,
	)
	if err != nil {
		t.Fatalf("cannot encrypt the key: %v", err)
	}

	ephemeralPublicKey, ok := parameters.EphemeralPublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", parameters.EphemeralPublicKey)
	}

	if ephemeralPublicKey.Curve != recipientKey.Curve {
		t.Errorf(
			"the ephemeral key is on %s, want %s",
			ephemeralPublicKey.Curve.Params().Name, recipientKey.Curve.Params().Name,
		)
	}

	if ephemeralPublicKey.Equal(&recipientKey.PublicKey) {
		t.Error("the ephemeral key is the key of the recipient")
	}

	agreedKey, err := jwa.ECDHES().DecryptKey(
		[]byte{}, recipientKey, jwa.A128GCM(), parameters,
	)
	if err != nil {
		t.Fatalf("cannot agree from the published key: %v", err)
	}

	if !bytes.Equal(contentEncryptionKey, agreedKey) {
		t.Errorf(
			"the recipient derived a different key:\n%x\n%x", contentEncryptionKey, agreedKey,
		)
	}
}

func TestECDHESAgreesWithAnX25519Recipient(t *testing.T) {
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot make a recipient key: %v", err)
	}

	parameters := new(jwa.KeyParameters)

	contentEncryptionKey, _, err := jwa.ECDHES().EncryptKey(
		recipientKey.PublicKey(), jwa.A128GCM(), parameters,
	)
	if err != nil {
		t.Fatalf("cannot encrypt the key: %v", err)
	}

	ephemeralPublicKey, ok := parameters.EphemeralPublicKey.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdh.PublicKey", parameters.EphemeralPublicKey)
	}

	if ephemeralPublicKey.Curve() != ecdh.X25519() {
		t.Errorf("the ephemeral key is on %s, want X25519", curve.Name(ephemeralPublicKey.Curve()))
	}

	agreedKey, err := jwa.ECDHES().DecryptKey(
		[]byte{}, recipientKey, jwa.A128GCM(), parameters,
	)
	if err != nil {
		t.Fatalf("cannot agree from the published key: %v", err)
	}

	if !bytes.Equal(contentEncryptionKey, agreedKey) {
		t.Errorf(
			"the recipient derived a different key:\n%x\n%x", contentEncryptionKey, agreedKey,
		)
	}
}
