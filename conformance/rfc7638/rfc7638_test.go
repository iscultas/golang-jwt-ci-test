package rfc7638_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"math/big"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

// rfc-req: RFC7638-S3-R01a
//
// RFC 7638 section 3, step 1 (keyword-free, promoted): the hash input JSON
// object contains "only the required members of a JWK representing the key".
// Restated in section 3.2 ("Only the required members of a key's
// representation are used") and explained in 3.2.2 (the thumbprint must not
// change with the presence or absence of an unrelated attribute).
func TestOptionalMembersDoNotAffectTheThumbprint(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	bare := jwk.NewKey(&key.PublicKey)
	decorated := jwk.NewKey(&key.PublicKey,
		jwk.WithID("2011-04-29"),
		jwk.WithAlgorithm(jwa.RS256()),
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Verify),
	)

	bareID, err := bare.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	decoratedID, err := decorated.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if bareID != decoratedID {
		t.Errorf("got thumbprints %q and %q, want the same value regardless of kid/alg/use/key_ops", bareID, decoratedID)
	}
}

// rfc-req: RFC7638-S3-R01b, RFC7638-S3-R01c, RFC7638-S3-R02
//
// RFC 7638 section 3 defines the thumbprint as: (1) build a JSON object of
// the required members only, with no whitespace or line breaks, ordered
// lexicographically by the Unicode code points of the member names, then (2)
// hash its UTF-8 octets with a hash function H. Section 3.1 works this
// computation for a concrete RSA key and publishes the SHA-256 result. No
// black-box test can separate "no whitespace" from "correct member order"
// from "hashed the right bytes" -- only their combination is observable -- so
// one test against the RFC's own worked example earns all three.
func TestWorkedExampleThumbprintMatchesTheRFC(t *testing.T) {
	const modulus = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_" +
		"BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368" +
		"QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr" +
		"3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const wantThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	n, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		t.Fatal(err)
	}

	key := jwk.NewKey(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 0x10001},
		jwk.WithAlgorithm(jwa.RS256()), jwk.WithID("2011-04-29"))

	got, err := key.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if got != wantThumbprint {
		t.Errorf("got thumbprint %q, want %q (RFC 7638 section 3.1)", got, wantThumbprint)
	}
}

// rfc-req: RFC7638-S3_2-R01
//
// RFC 7638 section 3.2 (keyword-free, promoted): "The required members for an
// elliptic curve public key ... are: crv, kty, x, y."
func TestRequiredMembersForEllipticCurveKey(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		requireExactMemberSet(t, jwk.NewKey(&privateKey.PublicKey), []string{"crv", "kty", "x", "y"})
	}
}

// rfc-req: RFC7638-S3_2-R02
//
// RFC 7638 section 3.2 (keyword-free, promoted): "The required members for an
// RSA public key ... are: e, kty, n." TestPrivateKeyThumbprintEqualsPublicKeyThumbprint
// separately confirms that a private key's d/p/q/dp/dq/qi members -- which an
// RSA JWK may also carry -- play no part in the thumbprint either.
func TestRequiredMembersForRSAKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	requireExactMemberSet(t, jwk.NewKey(&privateKey.PublicKey), []string{"e", "kty", "n"})
}

// rfc-req: RFC7638-S3_2-R03
//
// RFC 7638 section 3.2 (keyword-free, promoted): "The required members for a
// symmetric key ... are: k, kty." A symmetric key has no public/private
// split, so unlike RFC7638-S3_2-R01/R02 there is no second variant of this
// test to write: the one member set covers every oct key this package builds.
func TestRequiredMembersForSymmetricKey(t *testing.T) {
	requireExactMemberSet(t, jwk.NewKey([]byte("a symmetric key value")), []string{"k", "kty"})
}

// rfc-req: RFC7638-S3_2_1-R01
//
// RFC 7638 section 3.2.1 (keyword-free, promoted): "The JWK Thumbprint of a
// JWK representing a private key is computed as the JWK Thumbprint of a JWK
// representing the corresponding public key." This is the guarantee that lets
// a producer holding a private key and a consumer holding only its public
// half agree on a kid without coordinating which half either one holds.
func TestPrivateKeyThumbprintEqualsPublicKeyThumbprint(t *testing.T) {
	t.Run("EllipticCurve", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		requireEqualThumbprints(t, jwk.NewKey(privateKey), jwk.NewKey(&privateKey.PublicKey))
	})

	t.Run("RSA", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		requireEqualThumbprints(t, jwk.NewKey(privateKey), jwk.NewKey(&privateKey.PublicKey))
	})

	t.Run("OctetKeyPair", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		requireEqualThumbprints(t, jwk.NewKey(privateKey), jwk.NewKey(publicKey))
	})
}

// rfc-req: RFC7638-S3_3-R01
//
// RFC 7638 section 3.3: "Characters in member names and member values MUST be
// represented without being escaped." jwk's own documentation records that
// the coordinate/modulus members feeding the thumbprint are encoded through
// the same routine Key.MarshalJSON uses for its own "x"/"y"/"n"/"e"/"k"
// members, so this is checked through the public encoding: none of a marshaled
// Key's required-member values, across every kty this package supports,
// contains a byte that RFC 7159 section 7 would require escaping.
func TestMemberValuesContainNoEscapedCharacters(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		key     *jwk.Key
		members []string
	}{
		"EllipticCurve": {jwk.NewKey(&ecdsaKey.PublicKey), []string{"crv", "kty", "x", "y"}},
		"RSA":           {jwk.NewKey(&rsaKey.PublicKey), []string{"e", "kty", "n"}},
		"OctetSequence": {jwk.NewKey([]byte("a symmetric key value")), []string{"k", "kty"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			document, err := json.Marshal(test.key)
			if err != nil {
				t.Fatal(err)
			}

			var members map[string]jsontext.Value
			if err := json.Unmarshal(document, &members); err != nil {
				t.Fatal(err)
			}

			for _, name := range test.members {
				value, ok := members[name]
				if !ok {
					t.Fatalf("document %s has no %q member", document, name)
				}

				for _, b := range value {
					if b == '\\' || b < 0x20 {
						t.Errorf("member %q = %s contains byte 0x%02X, want no character requiring JSON escaping", name, value, b)
					}
				}
			}
		})
	}
}

// rfc-req: RFC7638-S3_4-R01
//
// RFC 7638 section 3.4 (keyword-free by the RFC's own convention, promoted):
// "A specific hash function must be chosen by an application to compute the
// hash value of the hash input." H is a free variable throughout section 3;
// jwk.Key.Thumbprint takes it as a parameter rather than fixing one, so the
// digest -- and its length -- change with the caller's choice.
func TestHashFunctionIsCallerSelected(t *testing.T) {
	key := jwk.NewKey([]byte("a symmetric key value"))

	sha256Sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	sha512Sum, err := key.Thumbprint(crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	}

	if len(sha256Sum) != crypto.SHA256.Size() {
		t.Errorf("got a %d-byte digest for SHA-256, want %d", len(sha256Sum), crypto.SHA256.Size())
	}

	if len(sha512Sum) != crypto.SHA512.Size() {
		t.Errorf("got a %d-byte digest for SHA-512, want %d", len(sha512Sum), crypto.SHA512.Size())
	}

	if bytes.Equal(sha256Sum, sha512Sum[:crypto.SHA256.Size()]) {
		t.Errorf("SHA-256 and SHA-512 digests should not coincide")
	}
}

// rfc-req: RFC7638-S3_5-R01
//
// RFC 7638 section 3.5: "a key need not be in JWK format to create a JWK
// Thumbprint of it. The only prerequisites are that the JWK representation of
// the key be defined and the party creating the JWK Thumbprint be in
// possession of the necessary key material." jwk.Key already wraps native Go
// crypto types rather than a JSON tree, so the JWK-format detour this
// requirement calls optional is never taken in the first place: a Key built
// directly from native material and one round-tripped through JWK JSON give
// the same thumbprint.
func TestThumbprintFromNativeKeyMaterialMatchesFromDecodedJWK(t *testing.T) {
	tests := map[string]*jwk.Key{}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests["EllipticCurve"] = jwk.NewKey(ecdsaKey)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests["RSA"] = jwk.NewKey(rsaKey)

	tests["OctetSequence"] = jwk.NewKey([]byte("a symmetric key value"))

	_, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests["OctetKeyPair"] = jwk.NewKey(ed25519Private)

	for name, native := range tests {
		t.Run(name, func(t *testing.T) {
			document, err := json.Marshal(native)
			if err != nil {
				t.Fatal(err)
			}

			decoded := new(jwk.Key)
			if err := json.Unmarshal(document, decoded); err != nil {
				t.Fatal(err)
			}

			requireEqualThumbprints(t, native, decoded)
		})
	}
}

func requireExactMemberSet(t *testing.T, key *jwk.Key, expected []string) {
	t.Helper()

	document, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}

	var members map[string]jsontext.Value
	if err := json.Unmarshal(document, &members); err != nil {
		t.Fatal(err)
	}

	want := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		want[name] = struct{}{}
		if _, ok := members[name]; !ok {
			t.Errorf("document %s is missing required member %q", document, name)
		}
	}

	for name := range members {
		if _, ok := want[name]; !ok {
			t.Errorf("document %s has member %q, which section 3.2 does not list as required", document, name)
		}
	}
}

func requireEqualThumbprints(t *testing.T, a, b *jwk.Key) {
	t.Helper()

	aID, err := a.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	bID, err := b.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if aID != bID {
		t.Errorf("got thumbprints %q and %q, want the same value", aID, bID)
	}
}
