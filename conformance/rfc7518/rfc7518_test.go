package rfc7518_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

// RFC 7518 section 2, Base64urlUInt (MUST): "The octet sequence MUST utilize
// the minimum number of octets needed to represent the value."
//
// rfc-req: RFC7518-S2-R01
func TestBase64urlUIntUsesTheMinimumNumberOfOctets(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	members := marshalledMembers(t, jwk.NewKey(&key.PublicKey))

	exponent := decodeMember(t, members, "e")
	if len(exponent) != 3 {
		t.Errorf("e: got %d octets, want 3 for the exponent 65537", len(exponent))
	}

	modulus := decodeMember(t, members, "n")
	if len(modulus) == 0 || modulus[0] == 0 {
		t.Errorf("n: got a leading octet of %v, want a non-zero one", modulus[:min(1, len(modulus))])
	}

	if got := len(modulus); got != 256 {
		t.Errorf("n: got %d octets, want 256 for a 2048-bit modulus", got)
	}
}

// RFC 7518 section 3.1 (MUST, promoted from the Implementation Requirements
// column): HS256's entry reads "Required", the strongest strength the table
// uses.
//
// rfc-req: RFC7518-S3_1-R01
func TestRequiredAlgorithmIsImplemented(t *testing.T) {
	algorithm, ok := jwa.ByName("HS256")
	if !ok {
		t.Fatal("HS256 does not resolve, but its Implementation Requirements entry is Required")
	}

	signer, ok := algorithm.(jwa.Signer)
	if !ok {
		t.Fatal("HS256 does not implement jwa.Signer")
	}

	verifier, ok := algorithm.(jwa.Verifier)
	if !ok {
		t.Fatal("HS256 does not implement jwa.Verifier")
	}

	key := secret("required-algorithm")

	signature, err := signer.Sign([]byte("signing input"), key)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if err := verifier.Verify([]byte("signing input"), signature, key); err != nil {
		t.Errorf("HS256 round trip: got %v, want no error", err)
	}
}

// RFC 7518 section 3.1 (SHOULD, promoted): RS256 is "Recommended" and ES256 is
// "Recommended+", the "+" marking a strength the specification expects to raise
// in a future version.
//
// rfc-req: RFC7518-S3_1-R02
func TestRecommendedAlgorithmsAreImplemented(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC key: %v", err)
	}

	for _, testCase := range []struct {
		name            string
		private, public any
	}{
		{"RS256", rsaKey, &rsaKey.PublicKey},
		{"ES256", ecdsaKey, &ecdsaKey.PublicKey},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(testCase.name)
			if !ok {
				t.Fatalf("%s does not resolve, but it is Recommended", testCase.name)
			}

			signature, err := algorithm.(jwa.Signer).Sign([]byte("signing input"), testCase.private)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			if err := algorithm.(jwa.Verifier).Verify([]byte("signing input"), signature, testCase.public); err != nil {
				t.Errorf("round trip: got %v, want no error", err)
			}
		})
	}
}

// RFC 7518 section 3.1 (MAY, promoted): nine identifiers plus "none" are marked
// "Optional", so an implementation may offer them or not.
//
// The interop half is what carries the weight and is never skipped: whichever
// an implementation offers, a name it does not offer must be reported as
// unsupported rather than quietly resolved to something else.
//
// rfc-req: RFC7518-S3_1-R03
func TestOptionalAlgorithmsAreOfferedOrReportedUnsupported(t *testing.T) {
	optional := []string{
		"HS384", "HS512", "RS384", "RS512", "ES384", "ES512", "PS256", "PS384", "PS512", "none",
	}

	for _, name := range optional {
		if _, ok := jwa.ByName(name); !ok {
			t.Logf("%s is not implemented, which is conformant for an Optional algorithm", name)
		}
	}

	if algorithm, ok := jwa.ByName("HS255"); ok {
		t.Errorf("an unregistered alg resolved to %v, want it reported unsupported", algorithm)
	}

	unsupported := jwa.UnsupportedAlgorithm("HS255")
	if !errors.Is(unsupported, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want an error wrapping %v", unsupported, jwa.ErrUnsupportedAlgorithm)
	}
}

// RFC 7518 section 3.2 (MUST): "A key of the same size as the hash output (for
// instance, 256 bits for "HS256") or larger MUST be used with this algorithm."
//
// Both sides of the boundary are asserted. A check that rejected everything
// would pass a one-sided test just as well as a correct one.
//
// rfc-req: RFC7518-S3_2-R01
func TestHmacKeyIsAtLeastTheHashOutputSize(t *testing.T) {
	for _, testCase := range []struct {
		name string
		size int
	}{{"HS256", 32}, {"HS384", 48}, {"HS512", 64}} {
		t.Run(testCase.name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(testCase.name)
			if !ok {
				t.Skipf("%s is Optional and not implemented", testCase.name)
			}

			short := make([]byte, testCase.size-1)
			if _, err := algorithm.(jwa.Signer).Sign([]byte("input"), short); !errors.Is(err, jwa.ErrWeakKey) {
				t.Errorf("signing with %d octets: got %v, want %v", testCase.size-1, err, jwa.ErrWeakKey)
			}

			if err := algorithm.(jwa.Verifier).Verify([]byte("input"), nil, short); !errors.Is(err, jwa.ErrWeakKey) {
				t.Errorf("verifying with %d octets: got %v, want %v", testCase.size-1, err, jwa.ErrWeakKey)
			}

			exact := make([]byte, testCase.size)
			if _, err := algorithm.(jwa.Signer).Sign([]byte("input"), exact); err != nil {
				t.Errorf("signing with exactly %d octets: got %v, want no error", testCase.size, err)
			}
		})
	}
}

// RFC 7518 section 3.2 (MUST): "The comparison of the computed HMAC value to
// the JWS Signature value MUST be done in a constant-time manner to thwart
// timing attacks."
//
// Asserted at the source level rather than by measurement: timing inside a Go
// test process is not dependable enough to judge this, and the property is
// exactly "the comparison is the constant-time one". The same approach is used
// for RFC 7515 section 10.9, which states the same obligation.
//
// rfc-req: RFC7518-S3_2-R02
func TestHmacComparisonIsConstantTime(t *testing.T) {
	source, err := os.ReadFile("../../jwa/hmac_sha_2.go")
	if err != nil {
		t.Fatalf("cannot read the HMAC implementation: %v", err)
	}

	if !strings.Contains(string(source), "hmac.Equal(") {
		t.Error("expected the MAC comparison to use hmac.Equal, which is constant time")
	}

	for _, variable := range []string{"bytes.Equal(mac", "string(mac) =="} {
		if strings.Contains(string(source), variable) {
			t.Errorf("found %q: the MAC comparison must not fall back to a variable-time one", variable)
		}
	}
}

// RFC 7518 section 3.3 (MUST): "A key of size 2048 bits or larger MUST be used
// with these algorithms", for RSASSA-PKCS1-v1_5; and section 3.5 (MUST), the
// same sentence for RSASSA-PSS.
//
// 1024 bits rather than 512 is deliberate: crypto/rsa refuses to generate
// anything below 1024, so 1024 is the largest non-conformant key the standard
// library will produce.
//
// rfc-req: RFC7518-S3_3-R01, RFC7518-S3_5-R01
func TestRsaKeyIsAtLeast2048Bits(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("cannot generate a 1024-bit key: %v", err)
	}

	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a 2048-bit key: %v", err)
	}

	for _, name := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		t.Run(name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(name)
			if !ok {
				t.Skipf("%s is Optional and not implemented", name)
			}

			if _, err := algorithm.(jwa.Signer).Sign([]byte("input"), weak); !errors.Is(err, jwa.ErrWeakKey) {
				t.Errorf("signing with a 1024-bit key: got %v, want %v", err, jwa.ErrWeakKey)
			}

			if err := algorithm.(jwa.Verifier).Verify([]byte("input"), nil, &weak.PublicKey); !errors.Is(err, jwa.ErrWeakKey) {
				t.Errorf("verifying with a 1024-bit key: got %v, want %v", err, jwa.ErrWeakKey)
			}

			if _, err := algorithm.(jwa.Signer).Sign([]byte("input"), strong); err != nil {
				t.Errorf("signing with a 2048-bit key: got %v, want no error", err)
			}
		})
	}
}

// RFC 7518 section 3.4 (MUST NOT): "The octet sequence representations MUST NOT
// be shortened to omit any leading zero octets contained in the values."
//
// R and S are near-uniform over the curve order, so each has roughly a 1-in-256
// chance of a leading zero octet. Over this many signatures a shortening
// implementation would emit an undersized one with overwhelming probability,
// which makes the fixed width the observable form of the prohibition.
//
// rfc-req: RFC7518-S3_4-R01
func TestEcdsaSignatureRetainsLeadingZeroOctets(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	const signatures = 512

	for i := range signatures {
		signature, err := jwa.ES256().Sign([]byte{byte(i), byte(i >> 8)}, key)
		if err != nil {
			t.Fatalf("cannot sign: %v", err)
		}

		if len(signature) != 64 {
			t.Fatalf("signature %d: got %d octets, want 64 with leading zeros retained", i, len(signature))
		}
	}
}

// RFC 7518 section 3.4 (MUST): "The JWS Signature value MUST be a 64-octet
// sequence. If it is not a 64-octet sequence, the validation has failed."
//
// rfc-req: RFC7518-S3_4-R02
func TestES256SignatureIsA64OctetSequence(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	signature, err := jwa.ES256().Sign([]byte("signing input"), key)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if len(signature) != 64 {
		t.Fatalf("got %d octets, want 64", len(signature))
	}

	for _, wrong := range [][]byte{signature[:63], append(append([]byte{}, signature...), 0)} {
		if err := jwa.ES256().Verify([]byte("signing input"), wrong, &key.PublicKey); !errors.Is(
			err, jwa.ErrMalformedSignature,
		) {
			t.Errorf(
				"verifying a %d-octet signature: got %v, want %v",
				len(wrong), err, jwa.ErrMalformedSignature,
			)
		}
	}
}

// RFC 7518 section 3.4 (MUST, promoted): "This specification defines the use of
// ECDSA with the P-256 curve and the SHA-256 cryptographic hash function, ECDSA
// with the P-384 curve and the SHA-384 hash function, and ECDSA with the P-521
// curve and the SHA-512 hash function", restated in the section 3.1 table as
// ES256 / ES384 / ES512.
//
// The pairing carries no BCP 14 keyword, but the keyworded length rule tested
// above depends on it: only a P-256 key yields the 64 octets ES256 requires.
//
// rfc-req: RFC7518-S3_4-R03
func TestEcdsaAlgorithmIsBoundToItsCurve(t *testing.T) {
	curves := map[string]elliptic.Curve{
		"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521(),
	}

	for _, testCase := range []struct {
		name  string
		curve string
	}{{"ES256", "P-256"}, {"ES384", "P-384"}, {"ES512", "P-521"}} {
		t.Run(testCase.name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(testCase.name)
			if !ok {
				t.Skipf("%s is Optional and not implemented", testCase.name)
			}

			for name, curve := range curves {
				key, err := ecdsa.GenerateKey(curve, rand.Reader)
				if err != nil {
					t.Fatalf("cannot generate a %s key: %v", name, err)
				}

				signature, signErr := algorithm.(jwa.Signer).Sign([]byte("signing input"), key)

				if name == testCase.curve {
					if signErr != nil {
						t.Errorf("%s with its own %s curve: got %v, want no error", testCase.name, name, signErr)
						continue
					}

					if err := algorithm.(jwa.Verifier).Verify(
						[]byte("signing input"), signature, &key.PublicKey,
					); err != nil {
						t.Errorf("%s round trip on %s: %v", testCase.name, name, err)
					}

					continue
				}

				if !errors.Is(signErr, jwa.ErrInvalidKeyType) {
					t.Errorf("%s signing with a %s key: got %v, want %v", testCase.name, name, signErr, jwa.ErrInvalidKeyType)
				}

				verifyErr := algorithm.(jwa.Verifier).Verify([]byte("signing input"), signature, &key.PublicKey)
				if !errors.Is(verifyErr, jwa.ErrInvalidKeyType) {
					t.Errorf(
						"%s verifying with a %s key: got %v, want %v",
						testCase.name, name, verifyErr, jwa.ErrInvalidKeyType,
					)
				}
			}
		})
	}
}

// RFC 7518 section 3.4 (MUST, promoted): "For ECDSA P-384 SHA-384, R and S will
// be 384 bits each, resulting in a 96-octet sequence. For ECDSA P-521 SHA-512,
// R and S will be 521 bits each, resulting in a 132-octet sequence."
//
// 132 rather than 130 is the figure worth pinning: P-521's 521-bit coordinates
// round up to 66 octets each, not 65.
//
// rfc-req: RFC7518-S3_4-R04
func TestES384AndES512SignatureLengths(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		curve  elliptic.Curve
		octets int
	}{{"ES384", elliptic.P384(), 96}, {"ES512", elliptic.P521(), 132}} {
		t.Run(testCase.name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(testCase.name)
			if !ok {
				t.Skipf("%s is Optional and not implemented", testCase.name)
			}

			key, err := ecdsa.GenerateKey(testCase.curve, rand.Reader)
			if err != nil {
				t.Fatalf("cannot generate key: %v", err)
			}

			signature, err := algorithm.(jwa.Signer).Sign([]byte("signing input"), key)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			if len(signature) != testCase.octets {
				t.Errorf("got %d octets, want %d", len(signature), testCase.octets)
			}

			short := signature[:len(signature)-1]
			if err := algorithm.(jwa.Verifier).Verify([]byte("signing input"), short, &key.PublicKey); !errors.Is(err, jwa.ErrMalformedSignature) {
				t.Errorf("verifying a %d-octet signature: got %v, want %v", len(short), err, jwa.ErrMalformedSignature)
			}
		})
	}
}

// RFC 7518 section 3.5 (MUST, promoted): RSASSA-PSS is used "with the MGF1
// mask generation function and SHA-2 hash functions, always using the same
// hash function for both the RSASSA-PSS hash function and the MGF1 hash
// function. The size of the salt value is the same size as the hash function
// output."
//
// The oracle is crypto/rsa's own verifier with PSSSaltLengthEqualsHash, which
// makes the salt length part of what is checked. This library's own Verify is
// deliberately lenient about salt length -- the RFC binds the producer -- so it
// cannot serve as the oracle here.
//
// rfc-req: RFC7518-S3_5-R02
func TestRsassaPssUsesASaltOfTheHashLength(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	for _, testCase := range []struct {
		name string
		hash crypto.Hash
	}{{"PS256", crypto.SHA256}, {"PS384", crypto.SHA384}, {"PS512", crypto.SHA512}} {
		t.Run(testCase.name, func(t *testing.T) {
			algorithm, ok := jwa.ByName(testCase.name)
			if !ok {
				t.Skipf("%s is Optional and not implemented", testCase.name)
			}

			input := []byte("signing input")

			signature, err := algorithm.(jwa.Signer).Sign(input, key)
			if err != nil {
				t.Fatalf("cannot sign: %v", err)
			}

			digest := testCase.hash.New()
			digest.Write(input)

			options := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: testCase.hash}
			if err := rsa.VerifyPSS(&key.PublicKey, testCase.hash, digest.Sum(nil), signature, options); err != nil {
				t.Errorf("verifying with a salt length equal to the hash: got %v, want no error", err)
			}
		})
	}
}

// RFC 7518 section 3.6 (MAY): "JWSs MAY also be created that do not provide
// integrity protection."
//
// rfc-req: RFC7518-S3_6-R01
func TestUnsecuredJwsMayBeCreated(t *testing.T) {
	algorithm, ok := jwa.ByName("none")
	if !ok {
		t.Skip("none is Optional and not implemented; the obligations that survive its absence are " +
			"tested by TestUnsecuredJwsIsRejectedByDefault")
	}

	signature, err := algorithm.(jwa.Signer).Sign([]byte("signing input"), nil)
	if err != nil {
		t.Fatalf("cannot produce an unsecured JWS: %v", err)
	}

	if len(signature) != 0 {
		t.Errorf("got a %d-octet signature, want the empty octet sequence", len(signature))
	}
}

// RFC 7518 section 3.6 (MUST): an Unsecured JWS "MUST use the empty octet
// sequence as its JWS Signature value".
//
// rfc-req: RFC7518-S3_6-R02
func TestUnsecuredJwsSignatureIsTheEmptyOctetSequence(t *testing.T) {
	token, err := jwt.NewToken(jwt.WithSignature(jwa.None(), nil))
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	parts := strings.Split(serialized, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}

	if parts[2] != "" {
		t.Errorf("got a signature part of %q, want it empty", parts[2])
	}
}

// RFC 7518 section 3.6 (MUST): "Recipients MUST verify that the JWS Signature
// value is the empty octet sequence."
//
// A token naming alg=none while carrying signature octets claims to be signed
// by the one algorithm that signs nothing. Reporting it verified would confirm
// that claim, so the check must hold even once a caller has allowed none.
//
// rfc-req: RFC7518-S3_6-R03
func TestUnsecuredJwsRequiresAnEmptySignature(t *testing.T) {
	if err := jwa.None().Verify([]byte("signing input"), []byte{}, nil); err != nil {
		t.Errorf("the empty signature: got %v, want no error", err)
	}

	for _, signature := range [][]byte{{0}, []byte("forged")} {
		if err := jwa.None().Verify([]byte("signing input"), signature, nil); err == nil {
			t.Errorf("a %d-octet signature under alg=none was accepted, want it refused", len(signature))
		}
	}
}

// RFC 7518 section 3.6 (MUST NOT): "Implementations that support Unsecured JWSs
// MUST NOT accept such objects as valid unless the application specifies that
// it is acceptable for a specific object to not be integrity protected."
//
// rfc-req: RFC7518-S3_6-R04
func TestUnsecuredJwsRequiresAnExplicitOptIn(t *testing.T) {
	parsed := unsecuredToken(t)

	if err := parsed.Verify(t.Context(), jwk.NewKeySet(), jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
		t.Errorf("without an opt-in: got %v, want %v", err, jwt.ErrForbiddenAlgorithm)
	}

	optedIn := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.None()))
	if err := parsed.Verify(t.Context(), jwk.NewKeySet(jwk.NewKey(secret("unused"))), optedIn); err != nil {
		t.Errorf("with an explicit opt-in: got %v, want no error", err)
	}
}

// RFC 7518 section 3.6 (MUST NOT): "Implementations MUST NOT accept Unsecured
// JWSs by default."
//
// This is the default-deny half, and it must hold with no configuration at all.
//
// rfc-req: RFC7518-S3_6-R05
func TestUnsecuredJwsIsRejectedByDefault(t *testing.T) {
	if err := unsecuredToken(t).Verify(t.Context(), jwk.NewKeySet(), jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
		t.Errorf("under the default configuration: got %v, want %v", err, jwt.ErrForbiddenAlgorithm)
	}

	if err := unsecuredToken(t).Verify(t.Context(), jwk.NewKeySet(), jwt.NewVerificationConfig()); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
		t.Errorf("under a freshly built default: got %v, want %v", err, jwt.ErrForbiddenAlgorithm)
	}
}

// RFC 7518 section 3.6 (MUST NOT): "applications MUST NOT signal acceptance of
// Unsecured JWSs at a global level, and SHOULD signal acceptance on a
// per-object basis."
//
// Addressed to applications, but a library offering only a global switch would
// make obeying it impossible. What is asserted is that acceptance travels with
// the call: allowing none once must leave the next call unaffected.
//
// rfc-req: RFC7518-S3_6-R06
func TestUnsecuredJwsAcceptanceIsPerCallRatherThanGlobal(t *testing.T) {
	parsed := unsecuredToken(t)
	keySet := jwk.NewKeySet(jwk.NewKey(secret("unused")))

	permissive := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.None()))
	if err := parsed.Verify(t.Context(), keySet, permissive); err != nil {
		t.Fatalf("the permissive config: got %v, want no error", err)
	}

	if err := parsed.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
		t.Errorf("the default config after a permissive one: got %v, want %v", err, jwt.ErrForbiddenAlgorithm)
	}
}

// RFC 7518 section 6.2.1 (MUST): crv and x "MUST be present for all Elliptic
// Curve public keys", and section 6.2.1 again (MUST) for y on the three curves
// this specification defines.
//
// rfc-req: RFC7518-S6_2_1-R01, RFC7518-S6_2_1-R02
func TestEllipticCurvePublicKeyRequiredMembers(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("cannot generate key: %v", err)
			}

			members := marshalledMembers(t, jwk.NewKey(&key.PublicKey))

			for _, name := range []string{"kty", "crv", "x", "y"} {
				if _, ok := members[name]; !ok {
					t.Errorf("member %q is absent, but it is required", name)
				}
			}

			for _, name := range []string{"crv", "x", "y"} {
				withoutMember := map[string]jsontext.Value{}
				for key, value := range members {
					if key != name {
						withoutMember[key] = value
					}
				}

				encoded, err := json.Marshal(withoutMember)
				if err != nil {
					t.Fatalf("cannot re-encode: %v", err)
				}

				var decoded jwk.Key
				err = json.Unmarshal(encoded, &decoded)

				if _, ok := errors.AsType[*jwk.MissingRequiredParameterError](err); !ok {
					t.Errorf("decoding without %q: got %v, want a *jwk.MissingRequiredParameterError", name, err)
				}
			}
		})
	}
}

// RFC 7518 sections 6.2.1.2 and 6.2.1.3 (MUST): "The length of this octet
// string MUST be the full size of a coordinate for the curve specified in the
// "crv" parameter", for x and y respectively; and section 6.2.2.1 (MUST) for d,
// "ceiling(log-base-2(n)/8) octets".
//
// P-521's 66 is the case worth naming: its 521-bit coordinates round up to 66
// octets, not the 65 a bit count alone would suggest.
//
// rfc-req: RFC7518-S6_2_1_2-R01, RFC7518-S6_2_1_3-R01, RFC7518-S6_2_2_1-R01
func TestEllipticCurveMemberWidths(t *testing.T) {
	for _, testCase := range []struct {
		curve  elliptic.Curve
		octets int
	}{{elliptic.P256(), 32}, {elliptic.P384(), 48}, {elliptic.P521(), 66}} {
		t.Run(testCase.curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(testCase.curve, rand.Reader)
			if err != nil {
				t.Fatalf("cannot generate key: %v", err)
			}

			members := marshalledMembers(t, jwk.NewKey(key))

			for _, name := range []string{"x", "y", "d"} {
				if got := len(decodeMember(t, members, name)); got != testCase.octets {
					t.Errorf("%s: got %d octets, want %d", name, got, testCase.octets)
				}
			}
		})
	}
}

// RFC 7518 section 6.2.2 (MUST): "the following member MUST be present to
// represent Elliptic Curve private keys", namely d.
//
// rfc-req: RFC7518-S6_2_2-R01
func TestEllipticCurvePrivateKeyIncludesD(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	private := jwk.NewKey(key)
	if _, ok := marshalledMembers(t, private)["d"]; !ok {
		t.Error("a private EC key marshalled without d")
	}

	if _, ok := marshalledMembers(t, private.Public())["d"]; ok {
		t.Error("Public() left d in place, which would publish the private scalar")
	}
}

// RFC 7518 section 6.3.1 (MUST): "The following members MUST be present for RSA
// public keys", namely n and e.
//
// rfc-req: RFC7518-S6_3_1-R01
func TestRsaPublicKeyRequiredMembers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	members := marshalledMembers(t, jwk.NewKey(&key.PublicKey))

	for _, name := range []string{"kty", "n", "e"} {
		if _, ok := members[name]; !ok {
			t.Errorf("member %q is absent, but it is required", name)
		}
	}

	for _, name := range []string{"n", "e"} {
		withoutMember := map[string]jsontext.Value{}
		for key, value := range members {
			if key != name {
				withoutMember[key] = value
			}
		}

		encoded, err := json.Marshal(withoutMember)
		if err != nil {
			t.Fatalf("cannot re-encode: %v", err)
		}

		var decoded jwk.Key
		err = json.Unmarshal(encoded, &decoded)

		if _, ok := errors.AsType[*jwk.MissingRequiredParameterError](err); !ok {
			t.Errorf("decoding without %q: got %v, want a *jwk.MissingRequiredParameterError", name, err)
		}
	}
}

// RFC 7518 section 6.3.1.2 (MUST): "when representing the value 65537, the
// octet sequence to be base64url-encoded MUST consist of the three octets
// [1, 0, 1]; the resulting representation for this value is "AQAB"".
//
// This is the specification's own worked value, so it is a published test
// vector rather than a restatement of the encoding rule.
//
// rfc-req: RFC7518-S6_3_1_2-R01
func TestRsaExponentForTheUsualValue(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	if key.E != 65537 {
		t.Skipf("crypto/rsa generated the exponent %d, not the 65537 this vector is written for", key.E)
	}

	members := marshalledMembers(t, jwk.NewKey(&key.PublicKey))

	var exponent string
	if err := json.Unmarshal(members["e"], &exponent); err != nil {
		t.Fatalf("cannot read e: %v", err)
	}

	if exponent != "AQAB" {
		t.Errorf("got e = %q, want \"AQAB\"", exponent)
	}

	if got := decodeMember(t, members, "e"); len(got) != 3 || got[0] != 1 || got[1] != 0 || got[2] != 1 {
		t.Errorf("got e decoding to %v, want [1 0 1]", got)
	}
}

// RFC 7518 section 6.3.2 (MUST): "The parameter "d" is REQUIRED for RSA private
// keys"; (SHOULD) the CRT parameters "enable optimizations and SHOULD be
// included by producers"; and (MUST) "If the producer includes any of the other
// private key parameters, then all of the others MUST be present".
//
// rfc-req: RFC7518-S6_3_2-R01, RFC7518-S6_3_2-R02, RFC7518-S6_3_2-R03
func TestRsaPrivateKeyParameters(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	private := jwk.NewKey(key)
	members := marshalledMembers(t, private)

	if _, ok := members["d"]; !ok {
		t.Error("a private RSA key marshalled without d, which is required")
	}

	if _, ok := marshalledMembers(t, private.Public())["d"]; ok {
		t.Error("Public() left d in place, which would publish the private exponent")
	}

	optimisation := []string{"p", "q", "dp", "dq", "qi"}

	present := 0
	for _, name := range optimisation {
		if _, ok := members[name]; ok {
			present++
		}
	}

	if present != 0 && present != len(optimisation) {
		t.Errorf("got %d of the %d optimisation parameters, want all or none", present, len(optimisation))
	}

	if present == 0 {
		t.Error("no optimisation parameters were included, which the SHOULD recommends against")
	}
}

// RFC 7518 section 6.3.2.7 (MUST): "When only two primes have been used (the
// normal case), this parameter MUST be omitted."
//
// rfc-req: RFC7518-S6_3_2_7-R01
func TestTwoPrimeRsaKeyOmitsOth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	if _, ok := marshalledMembers(t, jwk.NewKey(key))["oth"]; ok {
		t.Error("a two-prime RSA key carried an oth member, which must be omitted")
	}
}

// RFC 7518 section 6.3.2.7 (MUST NOT): "If the consumer of a JWK does not
// support private keys with more than two primes and it encounters a private
// key that includes the "oth" parameter, then it MUST NOT use the key."
//
// The fixture is written in the object form the RFC actually defines, rather
// than in whatever this package once emitted: what must be refused is a
// conformant document describing a key this package cannot use.
//
// rfc-req: RFC7518-S6_3_2_7-R03
func TestMultiPrimeRsaKeyIsRefused(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	members := marshalledMembers(t, jwk.NewKey(key))
	members["oth"] = jsontext.Value(`[{"r":"AQAB","d":"AQAB","t":"AQAB"}]`)

	encoded, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("cannot re-encode: %v", err)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(encoded, &decoded); !errors.Is(err, jwk.ErrMultiPrimeKey) {
		t.Errorf("got %v, want an error wrapping %v", err, jwk.ErrMultiPrimeKey)
	}

	multiPrime, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048) //nolint:staticcheck // The only constructor that makes a three-prime key, which is the key this test must refuse.
	if err != nil {
		t.Skipf("cannot generate a three-prime key: %v", err)
	}

	if _, err := json.Marshal(jwk.NewKey(multiPrime)); !errors.Is(err, jwk.ErrMultiPrimeKey) {
		t.Errorf("encoding a three-prime key: got %v, want %v", err, jwk.ErrMultiPrimeKey)
	}
}

// RFC 7518 section 6.4 (SHOULD): "An "alg" member SHOULD also be present to
// identify the algorithm intended to be used with the key, unless the
// application uses another means or convention to determine the algorithm
// used."
//
// The recommendation is addressed to whoever produces a JWK, and it carries its
// own escape clause, so what is asserted is that this library lets a producer
// follow it.
//
// rfc-req: RFC7518-S6_4-R01
func TestSymmetricKeyCanDeclareItsAlgorithm(t *testing.T) {
	key := jwk.NewKey(secret("symmetric"), jwk.WithAlgorithm(jwa.HS256()))

	members := marshalledMembers(t, key)

	var algorithm string
	if err := json.Unmarshal(members["alg"], &algorithm); err != nil {
		t.Fatalf("cannot read alg: %v", err)
	}

	if algorithm != "HS256" {
		t.Errorf("got alg %q, want \"HS256\"", algorithm)
	}

	if got := string(members["kty"]); got != `"oct"` {
		t.Errorf("got kty %s, want \"oct\"", got)
	}

	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("cannot encode: %v", err)
	}

	var decoded jwk.Key
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cannot decode: %v", err)
	}
}

func marshalledMembers(t *testing.T, key *jwk.Key) map[string]jsontext.Value {
	t.Helper()

	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	var members map[string]jsontext.Value
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("cannot read key members: %v", err)
	}

	return members
}

func decodeMember(t *testing.T, members map[string]jsontext.Value, name string) []byte {
	t.Helper()

	raw, ok := members[name]
	if !ok {
		t.Fatalf("member %q is absent", name)
	}

	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		t.Fatalf("member %q is not a string: %v", name, err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("member %q is not base64url: %v", name, err)
	}

	return decoded
}

func unsecuredToken(t *testing.T) *jwt.Token {
	t.Helper()

	token, err := jwt.NewToken(jwt.WithSignature(jwa.None(), nil))
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	parsed, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot parse token: %v", err)
	}

	return parsed
}

func secret(seed string) []byte {
	key := sha512.Sum512([]byte(seed))

	return key[:]
}
