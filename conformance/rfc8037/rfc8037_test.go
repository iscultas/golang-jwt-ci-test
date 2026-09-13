package rfc8037_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

const (
	privateJWK = `{"kty":"OKP","crv":"Ed25519",` +
		`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

	publicJWK = `{"kty":"OKP","crv":"Ed25519",` +
		`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

	privateKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	publicKeyHex  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

	canonicalForm          = `{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	canonicalFormDigestHex = "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"
	thumbprint             = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	signingInput = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	signature    = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	compactJWS   = signingInput + "." + signature
	payload      = "Example of Ed25519 signing"

	x25519JWK = `{"kty":"OKP","crv":"X25519","kid":"Bob",` +
		`"x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}`

	x25519PublicKeyHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

	ephemeralSecretHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

	ephemeralJWK = `{"kty":"OKP","crv":"X25519",` +
		`"x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}`

	ephemeralPublicKeyHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

	sharedSecretHex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

func parseKey(t *testing.T, document string) *jwk.Key {
	t.Helper()

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(document), key); err != nil {
		t.Fatalf("cannot parse JWK: %v", err)
	}

	return key
}

func members(t *testing.T, key *jwk.Key) map[string]any {
	t.Helper()

	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("cannot encode JWK: %v", err)
	}

	decoded := make(map[string]any)
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cannot decode the encoded JWK: %v", err)
	}

	return decoded
}

func decodeHex(t *testing.T, encoded string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("cannot decode hex: %v", err)
	}

	return decoded
}

// TestTheKeyTypeIsOKP covers RFC8037-S2-R01.
//
// RFC 8037 Section 2, MUST:
//
//	The parameter "kty" MUST be "OKP".
//
// The obligation is written for a producer, and both directions are asserted.
// The consumer half is the one with teeth: a reader that accepted an Ed25519
// subtype under some other key type would let one key be described two ways,
// which is the mixing up of algorithms Section 4 warns about.
//
// rfc-req: RFC8037-S2-R01
func TestTheKeyTypeIsOKP(t *testing.T) {
	for name, document := range map[string]string{"private": privateJWK, "public": publicJWK} {
		t.Run(name, func(t *testing.T) {
			key := parseKey(t, document)

			if key.Type() != jwk.OctetKeyPair {
				t.Errorf("got kty %q, want %q", key.Type(), jwk.OctetKeyPair)
			}

			if kty := members(t, key)["kty"]; kty != "OKP" {
				t.Errorf(`re-encoded key has "kty":%v, want "OKP"`, kty)
			}
		})
	}

	t.Run("AnEd25519CurveUnderAnotherKeyTypeIsRefused", func(t *testing.T) {
		document := `{"kty":"EC","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

		if err := json.Unmarshal([]byte(document), new(jwk.Key)); !errors.Is(err, jwk.ErrUnsupportedCurve) {
			t.Errorf("got error %v, want ErrUnsupportedCurve", err)
		}
	})
}

// TestTheSubtypeIsRequired covers RFC8037-S2-R02.
//
// RFC 8037 Section 2, MUST:
//
//	The parameter "crv" MUST be present and contain the subtype of the key
//	(from the "JSON Web Elliptic Curve" registry).
//
// rfc-req: RFC8037-S2-R02
func TestTheSubtypeIsRequired(t *testing.T) {
	t.Run("AbsentCrvIsReportedByName", func(t *testing.T) {
		document := `{"kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

		err := json.Unmarshal([]byte(document), new(jwk.Key))

		missing := new(jwk.MissingRequiredParameterError)
		if !errors.As(err, &missing) {
			t.Fatalf("got error %v, want a MissingRequiredParameterError", err)
		}
		if missing.Parameter != "crv" {
			t.Errorf("got parameter %q, want %q", missing.Parameter, "crv")
		}
	})

	t.Run("EveryEncodedKeyCarriesIt", func(t *testing.T) {
		for name, document := range map[string]string{"private": privateJWK, "public": publicJWK} {
			t.Run(name, func(t *testing.T) {
				if crv := members(t, parseKey(t, document))["crv"]; crv != jwk.Ed25519 {
					t.Errorf(`re-encoded key has "crv":%v, want %q`, crv, jwk.Ed25519)
				}
			})
		}
	})
}

// TestThePublicKeyIsRequired covers RFC8037-S2-R03.
//
// RFC 8037 Section 2, MUST:
//
//	The parameter "x" MUST be present and contain the public key encoded
//	using the base64url [RFC4648] encoding.
//
// The published hexadecimal dump is what makes this a test of the member's
// meaning rather than of its presence: a JWK that merely round-tripped x as an
// opaque string would pass an equality check against the figure and still be
// reading the wrong octets as the key.
//
// rfc-req: RFC8037-S2-R03
func TestThePublicKeyIsRequired(t *testing.T) {
	t.Run("AbsentXIsReportedByName", func(t *testing.T) {
		err := json.Unmarshal([]byte(`{"kty":"OKP","crv":"Ed25519"}`), new(jwk.Key))

		missing := new(jwk.MissingRequiredParameterError)
		if !errors.As(err, &missing) {
			t.Fatalf("got error %v, want a MissingRequiredParameterError", err)
		}
		if missing.Parameter != "x" {
			t.Errorf("got parameter %q, want %q", missing.Parameter, "x")
		}
	})

	t.Run("XIsThePublishedPublicKey", func(t *testing.T) {
		material, ok := parseKey(t, publicJWK).Material().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("got material of type %T, want ed25519.PublicKey", parseKey(t, publicJWK).Material())
		}

		if !material.Equal(ed25519.PublicKey(decodeHex(t, publicKeyHex))) {
			t.Errorf("got public key %x, want %s", material, publicKeyHex)
		}
	})

	t.Run("AnXOfTheWrongWidthIsRefused", func(t *testing.T) {
		document := `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo1"}`

		if err := json.Unmarshal([]byte(document), new(jwk.Key)); !errors.Is(err, jwk.ErrMalformedKey) {
			t.Errorf("got error %v, want ErrMalformedKey", err)
		}
	})
}

// TestAPrivateKeyCarriesItsPrivateKeyInD covers RFC8037-S2-R04.
//
// RFC 8037 Section 2, MUST:
//
//	The parameter "d" MUST be present for private keys and contain the
//	private key encoded using the base64url encoding.
//
// The width is asserted, not just the presence. Go's ed25519.PrivateKey is the
// 64-octet expanded form, while RFC 8037's "d" is the 32-octet seed; writing
// the former would produce a member twice the size the RFC defines, which no
// other implementation could read.
//
// rfc-req: RFC8037-S2-R04
func TestAPrivateKeyCarriesItsPrivateKeyInD(t *testing.T) {
	key := parseKey(t, privateJWK)

	d, ok := members(t, key)["d"].(string)
	if !ok {
		t.Fatal("re-encoded private key has no d member")
	}

	seed, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		t.Fatalf("cannot decode d: %v", err)
	}

	if want := decodeHex(t, privateKeyHex); string(seed) != string(want) {
		t.Errorf("got d %x, want %s", seed, privateKeyHex)
	}

	t.Run("ADThatDoesNotMatchXIsRefused", func(t *testing.T) {
		document := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"oWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

		if err := json.Unmarshal([]byte(document), new(jwk.Key)); !errors.Is(err, jwk.ErrMalformedKey) {
			t.Errorf("got error %v, want ErrMalformedKey", err)
		}
	})
}

// TestAPublicKeyCarriesNoD covers RFC8037-S2-R05.
//
// RFC 8037 Section 2, MUST NOT:
//
//	This parameter MUST NOT be present for public keys.
//
// Asserted as the absence of the member rather than as an empty value: a d of
// "" or null would satisfy a string comparison against the A.2 figure while
// still being present, and presence is what the sentence prohibits.
//
// rfc-req: RFC8037-S2-R05
func TestAPublicKeyCarriesNoD(t *testing.T) {
	for name, key := range map[string]*jwk.Key{
		"the published public key":           parseKey(t, publicJWK),
		"the public half of the private key": parseKey(t, privateJWK).Public(),
	} {
		t.Run(name, func(t *testing.T) {
			encoded := members(t, key)

			if _, present := encoded["d"]; present {
				t.Errorf("public key carries a d member: %v", encoded)
			}

			if got, want := slices.Sorted(maps.Keys(encoded)), []string{"crv", "kty", "x"}; !slices.Equal(got, want) {
				t.Errorf("got members %v, want %v", got, want)
			}
		})
	}
}

// TestTheThumbprintCoversCrvKtyAndX covers RFC8037-S2-R06.
//
// RFC 8037 Section 2:
//
//	When calculating JWK Thumbprints [RFC7638], the three public key fields
//	are included in the hash input in lexicographic order: "crv", "kty", and
//	"x".
//
// Keyword-free but normative: it is the OKP row of RFC 7638 Section 3.2's
// table of required members, which that document could not carry because OKP
// did not exist when it was published. Without it an OKP thumbprint has no
// defined input.
//
// rfc-req: RFC8037-S2-R06
func TestTheThumbprintCoversCrvKtyAndX(t *testing.T) {
	digest := sha256.Sum256([]byte(canonicalForm))
	if got := hex.EncodeToString(digest[:]); got != canonicalFormDigestHex {
		t.Fatalf("the A.3 canonical form in this file hashes to %s, want %s", got, canonicalFormDigestHex)
	}
	if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != thumbprint {
		t.Fatalf("the A.3 digest encodes to %q, want %q", got, thumbprint)
	}

	for name, document := range map[string]string{"private": privateJWK, "public": publicJWK} {
		t.Run(name, func(t *testing.T) {
			got, err := parseKey(t, document).Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatalf("cannot compute thumbprint: %v", err)
			}

			if !bytes.Equal(got, digest[:]) {
				t.Errorf("got thumbprint %x, want %x", got, digest)
			}
		})
	}

	t.Run("OptionalMembersDoNotMoveIt", func(t *testing.T) {
		labelled := jwk.NewKey(
			parseKey(t, publicJWK).Material(),
			jwk.WithID("some-kid"),
			jwk.WithAlgorithm(jwa.EdDSA()),
			jwk.WithPublicKeyUse(jwk.Signature),
		)

		got, err := labelled.ThumbprintID(crypto.SHA256)
		if err != nil {
			t.Fatalf("cannot compute thumbprint: %v", err)
		}

		if got != thumbprint {
			t.Errorf("got thumbprint %q for a labelled key, want %q", got, thumbprint)
		}
	})
}

// TestANonCanonicalEncodingIsRefused covers RFC8037-S2-R07.
//
// RFC 4648 Section 3.5, reached through Section 2's citation of it for the
// encoding of "x" and "d", MAY:
//
//	In some environments, the alteration is critical and therefore decoders
//	MAY chose to reject an encoding if the pad bits have not been set to
//	zero.  The specification referring to this may mandate a specific
//	behaviour.
//
// RFC 8037 mandates nothing, so either choice conforms. This module takes the
// option, and this test asserts the capability rather than its absence.
//
// It used to assert the opposite. When this file was written the module decoded
// with base64.RawURLEncoding in its non-Strict form, and the test proved the
// interop obligation that comes with declining the option: two documents could
// decode to one key, and that key did not thereby acquire two names, because
// jwk builds a thumbprint from the decoded material re-encoded canonically
// rather than from the member as it arrived. That was true, and it remains
// true — but it only ever covered the thumbprint jwk computes. It said nothing
// about a thumbprint jwk is handed, and jwk.ParseThumbprintURI, which does
// exactly that, did not exist yet. There a non-canonical spelling did give one
// key a second name, in the one place this module offers a name for comparing.
// The IR entry for this requirement had left the question open in as many
// words; it is answered here.
//
// rfc-req: RFC8037-S2-R07
func TestANonCanonicalEncodingIsRefused(t *testing.T) {
	nonCanonical := strings.Replace(publicJWK, "PcHURo", "PcHURp", 1)
	if nonCanonical == publicJWK {
		t.Fatal("the A.2 vector in this file has drifted from the RFC")
	}

	if material := parseKey(t, publicJWK).Material().(ed25519.PublicKey); !material.Equal(
		ed25519.PublicKey(decodeHex(t, publicKeyHex)),
	) {
		t.Fatalf("got public key %x, want %s", material, publicKeyHex)
	}

	for name, document := range map[string]string{
		"non-zero pad bits":        nonCanonical,
		"base64url with padding":   strings.Replace(publicJWK, `PcHURo"`, `PcHURo="`, 1),
		"standard base64 alphabet": strings.Replace(publicJWK, "VS_7Ty", "VS/7Ty", 1),
		"line break":               strings.Replace(publicJWK, "PcHURo", "PcH\\nURo", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(document), new(jwk.Key)); err == nil {
				t.Error("accepted, want an error")
			}
		})
	}
}

// TestAnEdDSASubtypeIsRefusedForKeyAgreement covers RFC8037-S3_1-R01.
//
// RFC 8037 Section 3.1, MUST NOT:
//
//	The key type used with these keys is "OKP" and the algorithm used for
//	signing is "EdDSA".  These subtypes MUST NOT be used for Elliptic Curve
//	Diffie-Hellman Ephemeral Static (ECDH-ES).
//
// Driven from the parsed JWK rather than from hand-built material, because
// that is the path a key supplied by a peer actually takes.
//
// rfc-req: RFC8037-S3_1-R01
func TestAnEdDSASubtypeIsRefusedForKeyAgreement(t *testing.T) {
	material := parseKey(t, publicJWK).Material()

	for _, algorithm := range []jwa.Algorithm{
		jwa.ECDHES(), jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW(),
	} {
		t.Run(algorithm.String(), func(t *testing.T) {
			encrypter, ok := algorithm.(jwa.KeyEncrypter)
			if !ok {
				t.Fatalf("%s does not implement jwa.KeyEncrypter", algorithm)
			}

			key, _, err := encrypter.EncryptKey(material, jwa.A128GCM(), new(jwa.KeyParameters))
			if !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("got error %v, want ErrInvalidKeyType", err)
			}
			if key != nil {
				t.Errorf("a key was derived anyway: %x", key)
			}
		})
	}
}

// TestEdDSAIsTheAlgorithmIdentifier covers RFC8037-S3_1-R02.
//
// RFC 8037 Section 3.1:
//
//	For the purpose of using the Edwards-curve Digital Signature Algorithm
//	(EdDSA) for signing data using "JSON Web Signature (JWS)" [RFC7515],
//	algorithm "EdDSA" is defined here, to be applied as the value of the
//	"alg" parameter.
//
// Keyword-free but definitional: this sentence is what binds the octets on the
// wire to the operation. RFC 9864 Section 2.2 later registers a
// fully-specified "Ed25519" identifier for the same operation over the same
// keys, which this module also implements; the two are tested separately
// because they are separate wire values. See RFC9864-S2_2-R01a.
//
// rfc-req: RFC8037-S3_1-R02
func TestEdDSAIsTheAlgorithmIdentifier(t *testing.T) {
	algorithm, ok := jwa.ByName("EdDSA")
	if !ok {
		t.Fatal(`jwa.ByName("EdDSA") reports it unregistered`)
	}
	if algorithm.String() != "EdDSA" {
		t.Errorf("got String() %q, want %q", algorithm.String(), "EdDSA")
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("rfc8037"),
		jwt.WithSignature(jwa.EdDSA(), parseKey(t, privateJWK)),
	)
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	compact, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	encodedHeader, _, found := strings.Cut(compact, ".")
	if !found {
		t.Fatalf("got %q, want a compact serialization", compact)
	}

	protectedHeader, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		t.Fatalf("cannot decode the protected header: %v", err)
	}

	if !strings.Contains(string(protectedHeader), `"alg":"EdDSA"`) {
		t.Errorf(`got protected header %s, want it to carry "alg":"EdDSA"`, protectedHeader)
	}

	parsed, err := jwt.Unmarshal(compact)
	if err != nil {
		t.Fatalf("cannot parse the token back: %v", err)
	}

	keySet := jwk.NewKeySet(parseKey(t, publicJWK))
	if err := parsed.Verify(t.Context(), keySet, jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.EdDSA()))); err != nil {
		t.Errorf("cannot verify a token this module signed under EdDSA: %v", err)
	}
}

// TestTheVariantComesFromTheSubtype covers RFC8037-S3_1-R03.
//
// RFC 8037 Section 3.1:
//
//	The EdDSA variant used is determined by the subtype of the key (Ed25519
//	for "Ed25519" and Ed448 for "Ed448").
//
// This is the sentence that makes "EdDSA" usable at all, the identifier being
// polymorphic in the curve — the property RFC 9864 was later written to
// remove. The assertion worth making is the negative one: an implementation
// that ignored "crv" and applied Ed25519 to every OKP key would accept an
// Ed448 document and sign under the wrong scheme. Refusing the key is the
// conformant outcome for a module implementing one subtype; the variant is
// still being determined by the subtype, and the determination is that there
// is no implementation for it.
//
// rfc-req: RFC8037-S3_1-R03
func TestTheVariantComesFromTheSubtype(t *testing.T) {
	document := `{"kty":"OKP","crv":"Ed448","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

	if err := json.Unmarshal([]byte(document), new(jwk.Key)); !errors.Is(err, jwk.ErrUnsupportedCurve) {
		t.Errorf("got error %v, want ErrUnsupportedCurve", err)
	}

	if _, ok := parseKey(t, privateJWK).Material().(ed25519.PrivateKey); !ok {
		t.Errorf("crv Ed25519 did not yield an ed25519 private key")
	}
}

// TestThePublishedSignatureIsReproduced covers RFC8037-S3_1_1-R01.
//
// RFC 8037 Section 3.1.1:
//
//	Signing for these is performed by applying the signing algorithm defined
//	in [RFC8032] to the private key (as private key), public key (as public
//	key), and the JWS Signing Input (as message).  The resulting signature is
//	the JWS Signature.  All inputs and outputs are octet strings.
//
// Ed25519 is deterministic, so equality against the published signature is a
// sound oracle rather than a plausibility check: a signature computed here
// that drew on randomness could not reproduce one computed elsewhere.
//
// rfc-req: RFC8037-S3_1_1-R01
func TestThePublishedSignatureIsReproduced(t *testing.T) {
	decodedPayload, err := base64.RawURLEncoding.DecodeString(strings.Split(signingInput, ".")[1])
	if err != nil {
		t.Fatalf("cannot decode the payload: %v", err)
	}
	if string(decodedPayload) != payload {
		t.Errorf("got payload %q, want %q", decodedPayload, payload)
	}

	got, err := jwa.EdDSA().Sign([]byte(signingInput), parseKey(t, privateJWK).Material())
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if encoded := base64.RawURLEncoding.EncodeToString(got); encoded != signature {
		t.Fatalf("got signature %q, want %q", encoded, signature)
	}

	if serialized := signingInput + "." + base64.RawURLEncoding.EncodeToString(got); serialized != compactJWS {
		t.Errorf("got compact serialization %q, want %q", serialized, compactJWS)
	}
}

// TestThePublishedSignatureVerifies covers RFC8037-S3_1_2-R01.
//
// RFC 8037 Section 3.1.2:
//
//	Verification is performed by applying the verification algorithm defined
//	in [RFC8032] to the public key (as public key), the JWS Signing Input (as
//	message), and the JWS Signature (as signature).  All inputs are octet
//	strings.  If the algorithm accepts, the signature is valid; otherwise,
//	the signature is invalid.
//
// The two negative cases are what stop this passing vacuously: a verifier that
// returned true for the published vector while ignoring its inputs would
// satisfy the positive case alone.
//
// Appendix A.5's closing prose gives the recovered message as "Example of
// Ed25519 Signing" with a capital S, while the payload it decodes carries a
// lowercase one. The encoded form is authoritative and is what is used here;
// no erratum is on file for the prose (the document's only reported erratum,
// 5329, is against Section 4).
//
// rfc-req: RFC8037-S3_1_2-R01
func TestThePublishedSignatureVerifies(t *testing.T) {
	material := parseKey(t, publicJWK).Material()

	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("cannot decode the signature: %v", err)
	}

	if err := jwa.EdDSA().Verify([]byte(signingInput), decodedSignature, material); err != nil {
		t.Errorf("the signature RFC 8037 Appendix A.5 declares valid did not verify: %v", err)
	}

	t.Run("AFlippedSignatureBitIsInvalid", func(t *testing.T) {
		tampered := slices.Clone(decodedSignature)
		tampered[0] ^= 1

		err := jwa.EdDSA().Verify([]byte(signingInput), tampered, material)
		if !errors.Is(err, jwa.ErrSignatureMismatch) {
			t.Errorf("a signature with one bit flipped: got %v, want %v", err, jwa.ErrSignatureMismatch)
		}
	})

	t.Run("AnAlteredSigningInputIsInvalid", func(t *testing.T) {
		tampered := strings.Replace(signingInput, "RXhhbXBsZ", "RXhhbXBsZQ", 1)

		err := jwa.EdDSA().Verify([]byte(tampered), decodedSignature, material)
		if !errors.Is(err, jwa.ErrSignatureMismatch) {
			t.Errorf("an altered signing input: got %v, want %v", err, jwa.ErrSignatureMismatch)
		}
	})
}

// TestAnECDHSubtypeNeverBecomesSigningMaterial covers RFC8037-S3_2-R01.
//
// RFC 8037 Section 3.2, MUST NOT:
//
//	The key type used with these keys is "OKP".  These subtypes MUST NOT be
//	used for signing.
//
// This test used to prove nothing, and said so. While no ECDH subtype could be
// parsed, the prohibition was met by a condition stronger than it asks for --
// the material could not exist -- and the note here read: "If X25519 or X448 is
// ever implemented for ECDH-ES, this test keeps passing while proving nothing,
// and a real check has to be written." X25519 is implemented now, so this is
// that check.
//
// What enforces the rule is the key type each signing algorithm demands.
// EdDSA.Sign takes an ed25519.PrivateKey and EdDSA.Verify an
// ed25519.PublicKey; an X25519 key is neither, so it is refused by name rather
// than by a subtype test written specially for this requirement. That is worth
// stating plainly: no code was added to satisfy this MUST NOT, and what the
// test asserts is that the existing check covers the case the RFC names.
//
// Selection is asserted alongside, because refusal at the algorithm is only
// half an answer if a key set hands the signer the wrong key to begin with.
//
// rfc-req: RFC8037-S3_2-R01
func TestAnECDHSubtypeNeverBecomesSigningMaterial(t *testing.T) {
	material := parseKey(t, x25519JWK).Material()

	if _, ok := material.(*ecdh.PublicKey); !ok {
		t.Fatalf("the X25519 JWK parsed to %T, want *ecdh.PublicKey", material)
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an X25519 key: %v", err)
	}

	for _, algorithm := range []jwa.Algorithm{jwa.EdDSA(), jwa.Ed25519()} {
		t.Run(algorithm.String(), func(t *testing.T) {
			signer, ok := algorithm.(jwa.Signer)
			if !ok {
				t.Fatalf("%s does not implement jwa.Signer", algorithm)
			}

			if _, err := signer.Sign([]byte("payload"), privateKey); !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("signing with an X25519 private key gave %v, want ErrInvalidKeyType", err)
			}

			verifier, ok := algorithm.(jwa.Verifier)
			if !ok {
				t.Fatalf("%s does not implement jwa.Verifier", algorithm)
			}

			signature := make([]byte, ed25519.SignatureSize)
			if err := verifier.Verify([]byte("payload"), signature, material); !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("verifying against an X25519 public key gave %v, want ErrInvalidKeyType", err)
			}
		})
	}

	t.Run("KeySetSelection", func(t *testing.T) {
		for name, document := range map[string]string{
			"unlabelled": x25519JWK,
			"labelled for encryption": strings.Replace(
				x25519JWK, `"kty":"OKP"`, `"kty":"OKP","use":"enc"`, 1,
			),
		} {
			t.Run(name, func(t *testing.T) {
				token, err := jwt.NewToken(
					jwt.WithIssuer("joe"), jwt.WithSignature(jwa.EdDSA(), jwk.NewKey(ed25519PrivateKeyMaterial(t))),
				)
				if err != nil {
					t.Fatalf("cannot create token: %v", err)
				}

				parsed, err := jwt.Unmarshal(token.String())
				if err != nil {
					t.Fatalf("cannot parse: %v", err)
				}

				if err := parsed.Verify(t.Context(),
					jwk.NewKeySet(parseKey(t, document)), jwt.DefaultVerificationConfig,
				); err == nil {
					t.Error("an X25519 key verified an EdDSA signature")
				}
			})
		}
	})

	for _, name := range []string{"X25519", "X448"} {
		if algorithm, ok := jwa.ByName(name); ok {
			t.Errorf("jwa.ByName(%q) resolved to %v, want no algorithm", name, algorithm)
		}
	}
}

func ed25519PrivateKeyMaterial(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate an Ed25519 key: %v", err)
	}

	return privateKey
}

// TestTheWorkedExampleKeysParseToTheirPublishedOctets covers RFC8037-S3_2-R02
// and RFC8037-S5-R01e.
//
// RFC 8037 Section 3.2 defines the subtypes by a table binding each "crv" to
// the ECDH function it names:
//
//	"crv"             ECDH Function Applied
//	X25519            X25519
//	X448              X448
//
// Appendix A.6 publishes two X25519 keys as both a JWK and a hex dump, which is
// what makes this checkable as key material rather than as strings that merely
// round-trip. Both directions are asserted, because a decoder that dropped "crv"
// and read "x" anyway would pass a one-way test while binding the octets to no
// curve at all.
//
// rfc-req: RFC8037-S3_2-R02, RFC8037-S5-R01e
func TestTheWorkedExampleKeysParseToTheirPublishedOctets(t *testing.T) {
	for name, vector := range map[string]struct {
		document  string
		publicKey string
	}{
		"Bob":       {x25519JWK, x25519PublicKeyHex},
		"ephemeral": {ephemeralJWK, ephemeralPublicKeyHex},
	} {
		t.Run(name, func(t *testing.T) {
			key := parseKey(t, vector.document)

			if keyType := key.Type(); keyType != jwk.OctetKeyPair {
				t.Errorf("got kty %q, want %q", keyType, jwk.OctetKeyPair)
			}

			material, ok := key.Material().(*ecdh.PublicKey)
			if !ok {
				t.Fatalf("got material %T, want *ecdh.PublicKey", key.Material())
			}

			if material.Curve() != ecdh.X25519() {
				t.Error("the key is not on X25519")
			}

			if !bytes.Equal(material.Bytes(), decodeHex(t, vector.publicKey)) {
				t.Errorf("got public key %x, want %s", material.Bytes(), vector.publicKey)
			}

			encoded, err := json.Marshal(jwk.NewKey(material))
			if err != nil {
				t.Fatalf("cannot encode: %v", err)
			}

			var members map[string]string
			if err := json.Unmarshal(encoded, &members); err != nil {
				t.Fatalf("cannot read back: %v", err)
			}

			if members["kty"] != "OKP" || members["crv"] != "X25519" {
				t.Errorf(`got kty %q and crv %q, want "OKP" and "X25519"`, members["kty"], members["crv"])
			}

			if !strings.Contains(vector.document, `"x":"`+members["x"]+`"`) {
				t.Errorf("re-encoded x as %q, which is not the published one", members["x"])
			}
		})
	}
}

// TestTheEphemeralPublicKeyIsTheBasePointProduct covers RFC8037-S3_2_1-R01.
//
// RFC 8037 Section 3.2.1:
//
//	Apply the appropriate ECDH function to the ephemeral private key (as
//	scalar input) and the standard base point (as u-coordinate input).  The
//	base64url encoding of the output is the value for the "x" parameter of
//	the "epk" field.
//
// A.6 prints the ephemeral secret and, separately, the JWK of the public key it
// derives. Reading the first and asserting it serializes to the second is the
// whole of this requirement, and it is the half of A.6 that lives in jwk rather
// than in the agreement.
//
// rfc-req: RFC8037-S3_2_1-R01
func TestTheEphemeralPublicKeyIsTheBasePointProduct(t *testing.T) {
	document := `{"kty":"OKP","crv":"X25519","x":"` +
		base64.RawURLEncoding.EncodeToString(decodeHex(t, ephemeralPublicKeyHex)) + `","d":"` +
		base64.RawURLEncoding.EncodeToString(decodeHex(t, ephemeralSecretHex)) + `"}`

	privateKey, ok := parseKey(t, document).Material().(*ecdh.PrivateKey)
	if !ok {
		t.Fatal("the X25519 private JWK did not parse to an *ecdh.PrivateKey")
	}

	if !bytes.Equal(privateKey.Bytes(), decodeHex(t, ephemeralSecretHex)) {
		t.Errorf("got scalar %x, want %s", privateKey.Bytes(), ephemeralSecretHex)
	}

	encoded, err := json.Marshal(jwk.NewKey(privateKey.PublicKey()))
	if err != nil {
		t.Fatalf("cannot encode the public half: %v", err)
	}

	if string(encoded) != ephemeralJWK {
		t.Errorf("got %s, want the published %s", encoded, ephemeralJWK)
	}
}

// TestTheAppendixA6AgreementDerivesFromThePublishedZ covers RFC8037-S3_2_1-R02.
//
// RFC 8037 Section 3.2.1:
//
//	Apply the appropriate ECDH function to the ephemeral private key (as
//	scalar input) and receiver public key (as u-coordinate input).  The
//	output is the Z value.
//
// Z is not reachable from outside jwa — agree hands it straight to the KDF and
// returns only the derived key — so this reaches it the other way, by computing
// what the derived key must be if Z is the published one. The Concat KDF of
// Section 4.6.2 of RFC 7518 is written out here from the RFC rather than called
// from the module, so the comparison is against the specification and not
// against the implementation restated.
//
// The agreement is run from the ephemeral side, with Bob's public key as the
// "epk". A.6 does not publish Bob's private key, and it prints Z twice to make
// the point that either side computes it, so running it in this direction
// asserts the same value the appendix does.
//
// rfc-req: RFC8037-S3_2_1-R02
func TestTheAppendixA6AgreementDerivesFromThePublishedZ(t *testing.T) {
	ephemeralKey, err := ecdh.X25519().NewPrivateKey(decodeHex(t, ephemeralSecretHex))
	if err != nil {
		t.Fatalf("cannot read the ephemeral secret: %v", err)
	}

	recipientKey, ok := parseKey(t, x25519JWK).Material().(*ecdh.PublicKey)
	if !ok {
		t.Fatal("Bob's JWK did not parse to an *ecdh.PublicKey")
	}

	derivedKey, err := jwa.ECDHES().DecryptKey(
		[]byte{}, ephemeralKey, jwa.A128GCM(),
		&jwa.KeyParameters{EphemeralPublicKey: recipientKey},
	)
	if err != nil {
		t.Fatalf("cannot agree: %v", err)
	}

	expectedKey := concatKDF(decodeHex(t, sharedSecretHex), "A128GCM", jwa.A128GCM().KeySize())

	if !bytes.Equal(derivedKey, expectedKey) {
		t.Errorf("derived %x, want %x from the published Z %s", derivedKey, expectedKey, sharedSecretHex)
	}
}

func concatKDF(sharedSecret []byte, algorithmID string, size int) []byte {
	input := []byte{0, 0, 0, 1}
	input = append(input, sharedSecret...)

	input = binary.BigEndian.AppendUint32(input, uint32(len(algorithmID)))
	input = append(input, algorithmID...)

	input = binary.BigEndian.AppendUint32(input, 0)
	input = binary.BigEndian.AppendUint32(input, 0)

	input = binary.BigEndian.AppendUint32(input, uint32(size)*8)

	digest := sha256.Sum256(input)

	return digest[:size]
}

// TestAnX25519TokenRoundTrips covers RFC8037-S3_2-R03.
//
// The end-to-end shape the two halves above only reach separately: a JWT
// encrypted to Bob's published key, and read back with his private one. Section
// 3.2's closing sentence is what makes this the right composition — "Section 4.6
// of [RFC7518] defines the ECDH-ES algorithms" — so the subtype is used with the
// same four "alg" values the NIST curves are, and nothing about X25519 gets an
// algorithm identifier of its own.
//
// The epk the token carries is asserted to be an OKP JWK on X25519, since that
// is the part a peer has to read and the part that would silently go wrong if
// the curve were carried by the key's representation rather than by the
// document.
//
// rfc-req: RFC8037-S3_2-R03
func TestAnX25519TokenRoundTrips(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	for _, algorithm := range []*jwa.ECDHESAlgorithm{
		jwa.ECDHES(), jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW(),
	} {
		t.Run(algorithm.String(), func(t *testing.T) {
			token, err := jwt.NewToken(
				jwt.WithIssuer("joe"),
				jwt.WithEncryption(algorithm, jwa.A128GCM(), jwk.NewKey(privateKey.PublicKey())),
			)
			if err != nil {
				t.Fatalf("cannot create token: %v", err)
			}

			serialized := token.String()

			parsed, err := jwt.Unmarshal(serialized)
			if err != nil {
				t.Fatalf("cannot parse: %v", err)
			}

			if err := parsed.Decrypt(t.Context(),
				jwk.NewKeySet(jwk.NewKey(privateKey)), jwt.DefaultDecryptionConfig,
			); err != nil {
				t.Fatalf("cannot decrypt: %v", err)
			}

			if issuer := parsed.Issuer(); issuer != "joe" {
				t.Errorf("got issuer %q, want %q", issuer, "joe")
			}

			for name, value := range headerMembers(t, serialized)["epk"].(map[string]any) {
				switch name {
				case "kty":
					if value != "OKP" {
						t.Errorf(`epk kty is %q, want "OKP"`, value)
					}
				case "crv":
					if value != "X25519" {
						t.Errorf(`epk crv is %q, want "X25519"`, value)
					}
				case "x":
				default:
					t.Errorf("epk carries an unexpected member %q", name)
				}
			}
		})
	}
}

func headerMembers(t *testing.T, compact string) map[string]any {
	t.Helper()

	encoded, _, found := strings.Cut(compact, ".")
	if !found {
		t.Fatalf("%q is not a compact serialization", compact)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("cannot decode the protected header: %v", err)
	}

	members := make(map[string]any)
	if err := json.Unmarshal(decoded, &members); err != nil {
		t.Fatalf("cannot parse the protected header: %v", err)
	}

	return members
}

// TestSigningNeedsNoRandomness covers RFC8037-S4-R01.
//
// RFC 8037 Section 4, REQUIRED:
//
//	If key generation or batch signature verification is performed, a
//	well-seeded cryptographic random number generator is REQUIRED.  Signing
//	and non-batch signature verification are deterministic operations and do
//	not need random numbers of any kind.
//
// The guard is false for this module: it exposes no OKP key generation and
// verifies one signature at a time. The honest oracle is therefore the second
// sentence. Recorded rather than dismissed — were an Ed25519 key generator
// added here later, the REQUIRED half would become live, and the reproduction
// below would not notice its absence.
//
// rfc-req: RFC8037-S4-R01
func TestSigningNeedsNoRandomness(t *testing.T) {
	material := parseKey(t, privateJWK).Material()

	first, err := jwa.EdDSA().Sign([]byte(signingInput), material)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	second, err := jwa.EdDSA().Sign([]byte(signingInput), material)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if string(first) != string(second) {
		t.Error("signing the same input twice gave different signatures")
	}

	if encoded := base64.RawURLEncoding.EncodeToString(first); encoded != signature {
		t.Errorf("got signature %q, want the published %q", encoded, signature)
	}
}

// TestAlgorithmsRefuseKeyMaterialOfAnotherSubtype covers RFC8037-S4-R03.
//
// RFC 8037 Section 4:
//
//	Do not separate key material from information about what key subtype it
//	is for.  When using keys, check that the algorithm is compatible with the
//	key subtype for the key.  To do otherwise opens the system up to attacks
//	via mixing up algorithms.  It is particularly dangerous to mix up
//	signature and Message Authentication Code (MAC) algorithms.
//
// The section names the dangerous case itself, so that is the case tested
// first. The protection here is Go's type system rather than an explicit
// subtype check, and the limit that comes with it is worth stating: a caller
// who deliberately converts an ed25519.PublicKey to []byte defeats it. No
// library-side check can prevent that, and nothing on the JWK parsing path
// does it — the material a parsed OKP JWK yields keeps its named type.
//
// rfc-req: RFC8037-S4-R03
func TestAlgorithmsRefuseKeyMaterialOfAnotherSubtype(t *testing.T) {
	t.Run("AMACAlgorithmRefusesASignatureKey", func(t *testing.T) {
		if _, err := jwa.HS256().Sign([]byte(signingInput), parseKey(t, publicJWK).Material()); !errors.Is(err, jwa.ErrInvalidKeyType) {
			t.Errorf("got error %v, want ErrInvalidKeyType", err)
		}
	})

	t.Run("EdDSARefusesAnECDSAKey", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate a key: %v", err)
		}

		if _, err := jwa.EdDSA().Sign([]byte(signingInput), key); !errors.Is(err, jwa.ErrInvalidKeyType) {
			t.Errorf("got error %v, want ErrInvalidKeyType", err)
		}
	})

	t.Run("ECDSARefusesAnEd25519Key", func(t *testing.T) {
		material := parseKey(t, privateJWK).Material()

		if _, err := jwa.ES256().Sign([]byte(signingInput), material); !errors.Is(err, jwa.ErrInvalidKeyType) {
			t.Errorf("got error %v, want ErrInvalidKeyType", err)
		}
	})
}

// TestAKeyIdentifierInTheProtectedHeaderIsBound covers RFC8037-S4-R04.
//
// RFC 8037 Section 4:
//
//	Although for Ed25519 and Ed448, the signature binds the key used for
//	signing, do not assume this, as there are many signature algorithms that
//	fail to make such a binding.  If key-binding is desired, include the key
//	used for signing either inside the JWS protected header or the data to
//	sign.
//
// The condition is the application's to declare, which is why this is filed at
// MAY. The capability is available here, so it is tested rather than skipped:
// a statement about the signing key placed in the JWS Protected Header is
// covered by the signature, and rewriting it after the fact makes verification
// fail. The unprotected header would not do, and that asymmetry is the whole
// content of the recommendation.
//
// Not tested: Ed25519's own key-binding property. That is RFC 8032's to
// provide, and the section's advice is precisely not to lean on it.
//
// rfc-req: RFC8037-S4-R04
func TestAKeyIdentifierInTheProtectedHeaderIsBound(t *testing.T) {
	signingKey := jwk.NewKey(parseKey(t, privateJWK).Material(), jwk.WithID("signing-key"))

	token, err := jwt.NewToken(
		jwt.WithIssuer("rfc8037"),
		jwt.WithSignature(
			jwa.EdDSA(), signingKey,
			jws.WithProtectedHeader(header.WithKeyID("signing-key")),
		),
	)
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	compact, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d compact parts, want 3", len(parts))
	}

	protectedHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("cannot decode the protected header: %v", err)
	}
	if !strings.Contains(string(protectedHeader), `"kid":"signing-key"`) {
		t.Fatalf(`got protected header %s, want it to carry the kid`, protectedHeader)
	}

	otherMaterial := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	otherKey := jwk.NewKey(otherMaterial.Public(), jwk.WithID("other-key"))

	rewritten := strings.Replace(string(protectedHeader), `"kid":"signing-key"`, `"kid":"other-key"`, 1)
	if rewritten == string(protectedHeader) {
		t.Fatal("the protected header was not rewritten")
	}

	tampered := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(rewritten)), parts[1], parts[2],
	}, ".")

	parsed, err := jwt.Unmarshal(tampered)
	if err != nil {
		return
	}

	keySet := jwk.NewKeySet(
		jwk.NewKey(parseKey(t, publicJWK).Material(), jwk.WithID("signing-key")),
		otherKey,
	)

	if err := parsed.Verify(t.Context(), keySet, jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.EdDSA()))); err == nil {
		t.Error("a token whose protected-header kid was rewritten still verified")
	}
}

// TestTheSupportedOptionalRegistrations covers RFC8037-S5-R01a,
// RFC8037-S5-R01b and RFC8037-S5-R01c.
//
// RFC 8037 Section 5 registers the "OKP" key type, the "EdDSA" algorithm and
// the "Ed25519" curve, each with:
//
//	JOSE Implementation Requirements: Optional
//
// Optional is the normative content of a registry entry: it is what licenses
// an implementation to omit the thing registered. This module supports all
// three, so what is recorded here is that supporting them was a choice, and
// what is asserted is the narrow fact that the three names resolve.
//
// rfc-req: RFC8037-S5-R01a, RFC8037-S5-R01b, RFC8037-S5-R01c
func TestTheSupportedOptionalRegistrations(t *testing.T) {
	key := parseKey(t, publicJWK)

	if key.Type() != jwk.OctetKeyPair {
		t.Errorf("got kty %q, want %q", key.Type(), jwk.OctetKeyPair)
	}

	if _, ok := key.Material().(ed25519.PublicKey); !ok {
		t.Errorf("crv %q did not yield Ed25519 material", jwk.Ed25519)
	}

	algorithm, ok := jwa.ByName("EdDSA")
	if !ok {
		t.Fatal(`jwa.ByName("EdDSA") reports it unregistered`)
	}

	if _, ok := algorithm.(jwa.Signer); !ok {
		t.Error("EdDSA does not implement jwa.Signer")
	}
	if _, ok := algorithm.(jwa.Verifier); !ok {
		t.Error("EdDSA does not implement jwa.Verifier")
	}
}

// TestTheUnsupportedOptionalRegistrationsAreRefusedByName covers
// RFC8037-S5-R01d.
//
// RFC 8037 Section 5 registers the "Ed448" curve with:
//
//	JOSE Implementation Requirements: Optional
//
// This is the requirement carrying the interop obligation, and its test is
// never skipped, because an absent optional capability is exactly what it
// exists to prove. Silence would be the failure: a parser that dropped an
// unrecognized "crv" and read "x" anyway would hand a signer 32 octets of an
// undetermined scheme, which is the algorithm mixing Section 4 warns about.
//
// X448 is asserted alongside Ed448. Its registration belongs to Section 3.2
// rather than to this one, but its absence has the identical consequence and is
// caught by the identical check. X25519 used to be asserted here too and no
// longer is: it is implemented, and its parse is covered by
// TestTheWorkedExampleKeysParseToTheirPublishedOctets.
//
// Both remaining curves are absent for the same reason, and it is not a choice
// this module made. The standard library has no crypto/ed448, and its
// crypto/ecdh offers X25519 as its only non-NIST curve, so implementing either
// means taking a dependency from outside it.
//
// rfc-req: RFC8037-S5-R01d, RFC8037-S5-R01f
func TestTheUnsupportedOptionalRegistrationsAreRefusedByName(t *testing.T) {
	for _, curve := range []string{"Ed448", "X448"} {
		t.Run(curve, func(t *testing.T) {
			document := `{"kty":"OKP","crv":"` + curve +
				`","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

			err := json.Unmarshal([]byte(document), new(jwk.Key))
			if !errors.Is(err, jwk.ErrUnsupportedCurve) {
				t.Errorf("got error %v, want ErrUnsupportedCurve", err)
			}
		})
	}

	if algorithm, ok := jwa.ByName("Ed448"); ok {
		t.Errorf(`jwa.ByName("Ed448") resolved to %v, want no algorithm`, algorithm)
	}
}
