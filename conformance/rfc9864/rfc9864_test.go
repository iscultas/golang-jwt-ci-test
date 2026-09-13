package rfc9864_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

const (
	ed25519Seed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	ed25519PublicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

func decodeEd25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	seed, err := base64.RawURLEncoding.DecodeString(ed25519Seed)
	if err != nil {
		t.Fatalf("cannot decode seed: %v", err)
	}

	return ed25519.NewKeyFromSeed(seed)
}

func decodeEd25519PublicKeyMaterial(t *testing.T) ed25519.PublicKey {
	t.Helper()

	publicKey, err := base64.RawURLEncoding.DecodeString(ed25519PublicKey)
	if err != nil {
		t.Fatalf("cannot decode public key: %v", err)
	}

	return ed25519.PublicKey(publicKey)
}

var fullySpecifiedEdDSAIdentifiers = []string{"Ed25519", "Ed448"}

func TestFullySpecifiedEdDSAAlgorithmIdentifiers(t *testing.T) {
	for _, name := range fullySpecifiedEdDSAIdentifiers {
		t.Run(name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(name)

			t.Run("UnregisteredNameIsRejectedCleanly", func(t *testing.T) {
				// rfc-req: RFC9864-S2_2-R01a, RFC9864-S2_2-R01b
				//
				// This subtest is unconditional: it documents how this package
				// currently treats the name, regardless of whether it happens to be
				// registered. When registered, ByName trivially satisfies it; the
				// case that matters is the unregistered one below.
				if ok {
					return
				}

				err := jwa.UnsupportedAlgorithm(name)
				if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
					t.Fatalf("got %v, want ErrUnsupportedAlgorithm", err)
				}

				encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + name + `"}`))

				h := new(header.Header)
				if err := h.Unmarshal(encodedHeader); !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
					t.Errorf("parsing a header naming %q as alg: got error %v, want %v", name, err, jwa.ErrUnsupportedAlgorithm)
				}
			})

			if !ok {
				t.Skipf(
					"%s is not registered by this package; RFC 9864 Section 4.1.1 lists its JOSE Implementation "+
						"Requirement as Optional, so omitting it is conformant",
					name,
				)
			}

			signer, isSigner := algorithm.(jwa.Signer)
			verifier, isVerifier := algorithm.(jwa.Verifier)
			if !isSigner || !isVerifier {
				t.Fatalf("%s is registered but does not implement both jwa.Signer and jwa.Verifier", name)
			}

			if name != "Ed25519" {
				t.Skipf("%s is registered but this suite has no test vector wired up for it", name)
			}

			privateKey := decodeEd25519PrivateKey(t)
			publicKey := decodeEd25519PublicKeyMaterial(t)
			token := []byte("RFC 9864 Ed25519 conformance")

			signature, err := signer.Sign(token, privateKey)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			expectedSignature, err := jwa.EdDSA().Sign(token, privateKey)
			if err != nil {
				t.Fatalf("cannot sign with EdDSA for comparison: %v", err)
			}

			if string(signature) != string(expectedSignature) {
				t.Errorf(
					"%s produced a different signature than EdDSA over the same Ed25519 key and payload; "+
						"RFC 9864 Section 5 requires identical key representation and hence identical "+
						"cryptographic behavior, differing only in the alg value",
					name,
				)
			}

			if err := verifier.Verify(token, signature, publicKey); err != nil {
				t.Errorf("%s produced a signature that failed its own Verify: %v", name, err)
			}

			if algorithm.String() != name {
				t.Errorf("got String() %q, want %q", algorithm.String(), name)
			}
		})
	}
}

func TestFullySpecifiedIdentifierIsUsableEndToEnd(t *testing.T) {
	// rfc-req: RFC9864-S2_2-R01a
	algorithm, ok := jwa.ByName("Ed25519")
	if !ok {
		t.Skip(`"Ed25519" is not registered by this package (Optional per RFC 9864 Section 4.1.1)`)
	}

	signer, isSigner := algorithm.(jwa.Signer)
	if !isSigner {
		t.Fatal(`"Ed25519" is registered but does not implement jwa.Signer`)
	}

	privateKey := jwk.NewKey(decodeEd25519PrivateKey(t), jwk.WithAlgorithm(algorithm))

	token, err := jwt.NewToken(
		jwt.WithIssuer("rfc9864-conformance"),
		jwt.WithSignature(signer, privateKey),
	)
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	encodedProtectedHeader, _, _ := strings.Cut(serialized, ".")
	protectedHeader := new(header.Header)
	if err := protectedHeader.Unmarshal(encodedProtectedHeader); err != nil {
		t.Fatalf("cannot parse the protected header this package produced: %v", err)
	}
	if got := protectedHeader.Algorithm; got != algorithm {
		t.Errorf("got alg %v in the protected header, want Ed25519", got)
	}

	parsed, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot parse the token this package produced: %v", err)
	}

	publicKey := jwk.NewKey(decodeEd25519PublicKeyMaterial(t), jwk.WithAlgorithm(algorithm))

	if err := parsed.Verify(t.Context(), jwk.NewKeySet(publicKey), jwt.DefaultVerificationConfig); err != nil {
		t.Errorf(
			"verifying an Ed25519-signed token under the default config: %v; a registered "+
				"fully-specified identifier that the default allowlist rejects cannot be negotiated with",
			err,
		)
	}
}

func TestDeprecatedEdDSAIdentifierRemainsSupported(t *testing.T) {
	// rfc-req: RFC9864-S4_1_2-R01
	algorithm, ok := jwa.ByName("EdDSA")
	if !ok {
		t.Fatal(`"EdDSA" is no longer registered: Deprecated (Section 4.4) does not mean Prohibited ` +
			`(MUST NOT be used) -- removing it is a conformance regression, not a valid response to deprecation`)
	}

	signer, isSigner := algorithm.(jwa.Signer)
	verifier, isVerifier := algorithm.(jwa.Verifier)
	if !isSigner || !isVerifier {
		t.Fatal(`"EdDSA" is registered but no longer implements jwa.Signer and jwa.Verifier`)
	}

	privateKey := decodeEd25519PrivateKey(t)
	publicKey := decodeEd25519PublicKeyMaterial(t)
	token := []byte("still signable under the deprecated identifier")

	signature, err := signer.Sign(token, privateKey)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if err := verifier.Verify(token, signature, publicKey); err != nil {
		t.Errorf(`got unverified signature under the deprecated "EdDSA" identifier: %v`, err)
	}

	if _, replacementAvailable := jwa.ByName(fullySpecifiedEdDSAIdentifiers[0]); !replacementAvailable {
		t.Errorf(
			"SHOULD violation (RFC9864-S4_1_2-R01, strict): RFC 9864 recommends new deployments prefer a "+
				"fully-specified replacement (e.g. %q) over the deprecated \"EdDSA\" identifier, but this "+
				"package does not register one, so callers have no way to follow that recommendation",
			fullySpecifiedEdDSAIdentifiers[0],
		)
	}
}

func TestEd25519KeyRepresentationUnchangedFromEdDSA(t *testing.T) {
	// rfc-req: RFC9864-S5-R01
	ed25519Algorithm, ok := jwa.ByName("Ed25519")
	if !ok {
		t.Skip(`"Ed25519" is not registered by this package (Optional per RFC 9864 Section 4.1.1); ` +
			"Section 5's key-representation equivalence has no alg value to compare against yet")
	}

	privateKey := decodeEd25519PrivateKey(t)

	eddsaKey := jwk.NewKey(privateKey, jwk.WithAlgorithm(jwa.EdDSA()))
	ed25519Key := jwk.NewKey(privateKey, jwk.WithAlgorithm(ed25519Algorithm))

	eddsaJSON, err := json.Marshal(eddsaKey)
	if err != nil {
		t.Fatalf("cannot marshal EdDSA-bound key: %v", err)
	}
	ed25519JSON, err := json.Marshal(ed25519Key)
	if err != nil {
		t.Fatalf("cannot marshal Ed25519-bound key: %v", err)
	}

	var eddsaMembers, ed25519Members map[string]any
	if err := json.Unmarshal(eddsaJSON, &eddsaMembers); err != nil {
		t.Fatalf("cannot decode EdDSA-bound key: %v", err)
	}
	if err := json.Unmarshal(ed25519JSON, &ed25519Members); err != nil {
		t.Fatalf("cannot decode Ed25519-bound key: %v", err)
	}

	if eddsaMembers["alg"] != "EdDSA" {
		t.Errorf(`got alg %v in the EdDSA-bound encoding, want "EdDSA"`, eddsaMembers["alg"])
	}
	if ed25519Members["alg"] != "Ed25519" {
		t.Errorf(`got alg %v in the Ed25519-bound encoding, want "Ed25519"`, ed25519Members["alg"])
	}

	delete(eddsaMembers, "alg")
	delete(ed25519Members, "alg")

	if !reflect.DeepEqual(eddsaMembers, ed25519Members) {
		t.Errorf(
			"key representation differs beyond the alg member:\nEdDSA:   %s\nEd25519: %s",
			eddsaJSON, ed25519JSON,
		)
	}

	decoded := new(jwk.Key)
	if err := json.Unmarshal(ed25519JSON, decoded); err != nil {
		t.Fatalf("cannot decode Ed25519-bound key: %v", err)
	}

	decodedPrivateKey, ok := decoded.Material().(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("got material %T, want ed25519.PrivateKey", decoded.Material())
	}
	if !privateKey.Equal(decodedPrivateKey) {
		t.Error("key material did not round-trip through the Ed25519-bound encoding")
	}
}

func TestKeySelectionRejectsAlgorithmMismatch(t *testing.T) {
	// rfc-req: RFC9864-S7-R01
	key := jwk.NewKey([]byte("shared secret"), jwk.WithAlgorithm(jwa.HS256()))
	keySet := jwk.NewKeySet(key)

	if selected, err := keySet.Key("", nil, jwa.RS256(), ""); !errors.Is(err, jwk.ErrNoSuitableKey) {
		t.Fatalf(
			"selecting an HS256-bound key for RS256: got key %v, error %v, want %v",
			selected, err, jwk.ErrNoSuitableKey,
		)
	}

	selected, err := keySet.Key("", nil, jwa.HS256(), "")
	if err != nil {
		t.Fatalf("selecting the key for its own bound algorithm: %v", err)
	}
	if selected != key {
		t.Errorf("got key %v, want %v", selected, key)
	}
}

func TestAlgorithmParameterRoundTrips(t *testing.T) {
	// rfc-req: RFC9864-S7-R02
	key := jwk.NewKey([]byte("shared secret"), jwk.WithAlgorithm(jwa.HS256()))

	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("cannot marshal key: %v", err)
	}

	var members map[string]any
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	if members["alg"] != "HS256" {
		t.Fatalf(
			`got alg %v, want "HS256" -- if the library cannot round-trip the alg member, `+
				"callers have no way to follow RFC 9864 Section 7's recommendation to set it",
			members["alg"],
		)
	}

	decoded := new(jwk.Key)
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("cannot unmarshal key: %v", err)
	}

	keySet := jwk.NewKeySet(decoded)
	if _, err := keySet.Key("", nil, jwa.RS256(), ""); !errors.Is(err, jwk.ErrNoSuitableKey) {
		t.Error(
			"alg member did not survive the JSON round trip: a key decoded from JSON should still " +
				"refuse selection for a mismatched algorithm",
		)
	}
}

// TestJOSEKeyManagementIsFullySpecified checks that each "alg" this module
// implements determines its key establishment from the identifier alone.
//
// MUST — "To perform fully-specified encryption in JOSE, the "alg" value MUST
// specify all parameters for key establishment or derive some of them from the
// accompanying "enc" value".
//
// The observable form of "fully specified" is that nothing about the operation
// moves when the other algorithm changes. An A192KW that varied its cipher with
// the "enc" would show a different encrypted key length; a PBES2 variant that
// picked its PRF from anywhere but its own name would derive differently.
//
// Section 3 explicitly permits one derivation: "the keydatalen KDF parameter
// value for "ECDH-ES" is determined from the "enc" value ... deriving parameters
// from "enc" does not make the algorithm polymorphic". jwa does exactly that and
// no more; RFC7518-S4_6-R02 and -R03 assert it.
//
// The honest exception is the curve, and it is not fixable here. Sections 3.2 and
// 6.2 state that JOSE's ECDH identifiers are polymorphic because they do not name
// the elliptic curve, and RFC 9864 registers no fully-specified replacement. What
// this module does is bind the ephemeral curve to the recipient key's, refusing a
// cross-curve agreement — a mitigation for the consequence, not a cure for the
// polymorphism. Both halves are asserted below.
//
// rfc-req: RFC9864-S3-R01a
func TestJOSEKeyManagementIsFullySpecified(t *testing.T) {
	encryptions := []jwa.ContentEncrypter{
		jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
		jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
	}

	for _, pairing := range []struct {
		algorithm jwa.KeyEncrypter
		key       any
	}{
		{jwa.A128KW(), bytes.Repeat([]byte{7}, 16)},
		{jwa.A192KW(), bytes.Repeat([]byte{7}, 24)},
		{jwa.A256KW(), bytes.Repeat([]byte{7}, 32)},
		{jwa.A128GCMKW(), bytes.Repeat([]byte{7}, 16)},
		{jwa.A192GCMKW(), bytes.Repeat([]byte{7}, 24)},
		{jwa.A256GCMKW(), bytes.Repeat([]byte{7}, 32)},
	} {
		t.Run(pairing.algorithm.String(), func(t *testing.T) {
			overheads := map[int]bool{}

			for _, encryption := range encryptions {
				cek, encryptedKey, err := pairing.algorithm.EncryptKey(
					pairing.key, encryption, new(jwa.KeyParameters),
				)
				if err != nil {
					t.Fatalf("%s: %v", encryption, err)
				}

				overheads[len(encryptedKey)-len(cek)] = true
			}

			if len(overheads) != 1 {
				t.Errorf("the wrapping overhead varied with the enc: %v", overheads)
			}
		})
	}
}

// TestECDHESIsPolymorphicInItsCurve records the exception, and the mitigation.
//
// MUST — the same sentence as TestJOSEKeyManagementIsFullySpecified. Section 3.2:
// the ECDH algorithms "are polymorphic because they do not specify the elliptic
// curve to be used for the key". This module cannot make them otherwise — the
// identifier is what is underspecified, and RFC 9864 §6.2 declines to register a
// replacement — so what is asserted is the mitigation: a cross-curve agreement is
// refused rather than attempted.
//
// The demonstration below used to run over P-256 and P-384 alone, where the
// polymorphism was real but narrow: two curves of one family, agreed by one
// implementation, differing in width. With X25519 implemented it spans two curve
// families that share no arithmetic, no key representation and no encoding —
// under the identical "alg" string, whose value on the wire is the same six
// characters either way. That is the clearest statement the module can make of
// what §3.2 means, and it needed no argument, only a second family.
//
// rfc-req: RFC9864-S3-R01a
func TestECDHESIsPolymorphicInItsCurve(t *testing.T) {
	nistKey := func(t *testing.T, curve elliptic.Curve) any {
		t.Helper()

		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate a key: %v", err)
		}

		return &key.PublicKey
	}

	x25519PublicKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an X25519 key: %v", err)
	}

	for name, key := range map[string]any{
		"P-256":  nistKey(t, elliptic.P256()),
		"P-384":  nistKey(t, elliptic.P384()),
		"X25519": x25519PublicKey.PublicKey(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := jwa.ECDHES().EncryptKey(key, jwa.A128GCM(), new(jwa.KeyParameters)); err != nil {
				t.Errorf("ECDH-ES refused %s: %v", name, err)
			}
		})
	}

	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a recipient key: %v", err)
	}

	ephemeral, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an ephemeral key: %v", err)
	}

	for name, mismatch := range map[string]struct {
		recipientKey       any
		ephemeralPublicKey any
	}{
		"within the NIST family": {recipient, &ephemeral.PublicKey},
		"across families":        {recipient, x25519PublicKey.PublicKey()},
		"across families, other direction": {
			x25519PublicKey, &ephemeral.PublicKey,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := jwa.ECDHES().DecryptKey(
				nil, mismatch.recipientKey, jwa.A128GCM(),
				&jwa.KeyParameters{EphemeralPublicKey: mismatch.ephemeralPublicKey},
			)
			if !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("a cross-curve agreement gave %v, want ErrInvalidKeyType", err)
			}
		})
	}
}

// TestJOSEContentEncryptionIsFullySpecified checks that each "enc" fixes every
// parameter of the symmetric encryption.
//
// MUST — "the "enc" value MUST specify all parameters for symmetric encryption."
//
// Section 3.1 states the conclusion — "All the symmetric encryption algorithms
// registered by [RFC7518] ... are fully specified" — and this asserts it rather
// than restating it. Each of key length, IV length and tag length is a parameter
// that, left unspecified, a sender and recipient could disagree about.
//
// rfc-req: RFC9864-S3-R01b
func TestJOSEContentEncryptionIsFullySpecified(t *testing.T) {
	for _, encryption := range []struct {
		algorithm jwa.ContentEncrypter
		tag       int
	}{
		{jwa.A128CBCHS256(), 16},
		{jwa.A192CBCHS384(), 24},
		{jwa.A256CBCHS512(), 32},
		{jwa.A128GCM(), 16},
		{jwa.A192GCM(), 16},
		{jwa.A256GCM(), 16},
	} {
		t.Run(encryption.algorithm.String(), func(t *testing.T) {
			encryption := encryption
			cek := bytes.Repeat([]byte{3}, encryption.algorithm.KeySize())
			iv := bytes.Repeat([]byte{5}, encryption.algorithm.IVSize())

			_, tag, err := encryption.algorithm.Encrypt([]byte("plaintext"), cek, iv, nil)
			if err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}

			if len(tag) != encryption.tag {
				t.Errorf("tag is %d octets, want %d", len(tag), encryption.tag)
			}

			for _, size := range []int{encryption.algorithm.KeySize() - 1, encryption.algorithm.KeySize() + 1} {
				if _, _, err := encryption.algorithm.Encrypt(
					[]byte("plaintext"), bytes.Repeat([]byte{3}, size), iv, nil,
				); err == nil {
					t.Errorf("a %d-octet CEK was accepted", size)
				}
			}

			for _, size := range []int{encryption.algorithm.IVSize() - 1, encryption.algorithm.IVSize() + 1} {
				if _, _, err := encryption.algorithm.Encrypt(
					[]byte("plaintext"), cek, bytes.Repeat([]byte{5}, size), nil,
				); err == nil {
					t.Errorf("a %d-octet IV was accepted", size)
				}
			}
		})
	}
}
