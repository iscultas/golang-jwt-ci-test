package rfc9278_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/jwk"
)

const (
	exampleModulus = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
		"cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4" +
		"QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQF" +
		"h6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	exampleExponent = "AQAB"

	exampleURI = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
)

// RFC 9278 section 3 (MUST, promoted): "The following URI prefix is defined to
// indicate that the portion of the URI following the prefix is a JWK
// Thumbprint: urn:ietf:params:oauth:jwk-thumbprint".
//
// The expected prefix is written out here rather than taken from
// jwk.ThumbprintURIPrefix. Comparing the implementation's constant against
// itself would pass however that constant were spelled.
//
// rfc-req: RFC9278-S3-R01
func TestThumbprintURIHasTheRegisteredPrefix(t *testing.T) {
	const prefix = "urn:ietf:params:oauth:jwk-thumbprint"

	uri, err := exampleKey(t).ThumbprintURI(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot build URI: %v", err)
	}

	if !strings.HasPrefix(uri, prefix+":") {
		t.Errorf("got %q, want it to begin with %q", uri, prefix+":")
	}

	if jwk.ThumbprintURIPrefix != prefix {
		t.Errorf("jwk.ThumbprintURIPrefix is %q, want %q", jwk.ThumbprintURIPrefix, prefix)
	}
}

// RFC 9278 section 3 (MUST, promoted): "the prefix is followed by a hash
// algorithm identifier and a JWK Thumbprint value, each separated by a colon
// character to form a URI representing a JWK Thumbprint."
//
// Tying the final segment to ThumbprintID is what shows the URI carries the
// RFC 7638 thumbprint rather than some other digest of the same key.
//
// rfc-req: RFC9278-S3-R02
func TestThumbprintURIStructure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	for _, testCase := range []struct {
		hash crypto.Hash
		name string
	}{{crypto.SHA256, "sha-256"}, {crypto.SHA384, "sha-384"}, {crypto.SHA512, "sha-512"}} {
		t.Run(testCase.name, func(t *testing.T) {
			uri, err := jwk.NewKey(&key.PublicKey).ThumbprintURI(testCase.hash)
			if err != nil {
				t.Fatalf("cannot build URI: %v", err)
			}

			const prefix = "urn:ietf:params:oauth:jwk-thumbprint:"

			remainder, found := strings.CutPrefix(uri, prefix)
			if !found {
				t.Fatalf("got %q, want it to begin with %q", uri, prefix)
			}

			segments := strings.Split(remainder, ":")
			if len(segments) != 2 {
				t.Fatalf("got %d segments after the prefix in %q, want 2", len(segments), uri)
			}

			if segments[0] != testCase.name {
				t.Errorf("got hash identifier %q, want %q", segments[0], testCase.name)
			}

			thumbprintID, err := jwk.NewKey(&key.PublicKey).ThumbprintID(testCase.hash)
			if err != nil {
				t.Fatalf("cannot compute the thumbprint: %v", err)
			}

			if segments[1] != thumbprintID {
				t.Errorf("got thumbprint %q in the URI, want %q from ThumbprintID", segments[1], thumbprintID)
			}
		})
	}
}

// RFC 9278 section 4 (MUST): "Hash algorithm identifiers used in JWK Thumbprint
// URIs MUST be values from the "Hash Name String" column in the IANA "Named
// Information Hash Algorithm Registry"."
//
// The negative half is the one that bites. Go spells these hashes differently
// from the registry, so an implementation deriving the identifier by
// lowercasing crypto.Hash.String would emit "sha-1" for SHA-1 and look
// plausible while naming something the registry does not carry under that name.
//
// rfc-req: RFC9278-S4-R01
func TestHashIdentifiersComeFromTheRegistry(t *testing.T) {
	key := exampleKey(t)

	for _, testCase := range []struct {
		hash crypto.Hash
		name string
	}{{crypto.SHA256, "sha-256"}, {crypto.SHA384, "sha-384"}, {crypto.SHA512, "sha-512"}} {
		uri, err := key.ThumbprintURI(testCase.hash)
		if err != nil {
			t.Fatalf("%s: cannot build URI: %v", testCase.hash, err)
		}

		if !strings.Contains(uri, ":"+testCase.name+":") {
			t.Errorf("%s: got %q, want it to name the hash %q", testCase.hash, uri, testCase.name)
		}
	}

	for _, hash := range []crypto.Hash{crypto.MD5, crypto.SHA1, crypto.RIPEMD160, crypto.MD5SHA1} {
		uri, err := key.ThumbprintURI(hash)
		if !errors.Is(err, jwk.ErrUnregisteredHashName) {
			t.Errorf("%s: got (%q, %v), want an error wrapping %v", hash, uri, err, jwk.ErrUnregisteredHashName)
		}

		if uri != "" {
			t.Errorf("%s: got the URI %q alongside the error, want none", hash, uri)
		}
	}
}

// RFC 9278 section 5 (MUST, promoted): "To promote interoperability among
// implementations, the SHA-256 hash algorithm is mandatory to implement."
//
// That this test imports no hash package is part of the assertion: jwk links
// SHA-256 itself, so the guarantee holds for a caller who did nothing to
// arrange it.
//
// rfc-req: RFC9278-S5-R01
func TestSHA256IsMandatoryToImplement(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key: %v", err)
	}

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate Ed25519 key: %v", err)
	}

	for name, material := range map[string]any{
		"EllipticCurve": &ecdsaKey.PublicKey,
		"RSA":           &rsaKey.PublicKey,
		"OctetKeyPair":  publicKey,
		"OctetSequence": []byte("a symmetric key of sufficient length for HS512......"),
	} {
		t.Run(name, func(t *testing.T) {
			uri, err := jwk.NewKey(material).ThumbprintURI(crypto.SHA256)
			if err != nil {
				t.Fatalf("SHA-256 is mandatory to implement but failed: %v", err)
			}

			if !strings.Contains(uri, ":sha-256:") {
				t.Errorf("got %q, want it to name sha-256", uri)
			}
		})
	}
}

// RFC 9278 section 6 (MUST, promoted): "A complete JWK Thumbprint URI using the
// above JWK Thumbprint and SHA-256 hash algorithm is as follows:
// urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
//
// The specification's own worked value, so one assertion checks the prefix, the
// separators, the registry name and the underlying RFC 7638 computation at once
// against a figure nobody here chose.
//
// rfc-req: RFC9278-S6-R01
func TestWorkedExampleURIMatchesTheRFC(t *testing.T) {
	uri, err := exampleKey(t).ThumbprintURI(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot build URI: %v", err)
	}

	if uri != exampleURI {
		t.Errorf("got  %q\nwant %q", uri, exampleURI)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate key: %v", err)
	}

	private, err := jwk.NewKey(key).ThumbprintURI(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot build the private key's URI: %v", err)
	}

	public, err := jwk.NewKey(&key.PublicKey).ThumbprintURI(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot build the public key's URI: %v", err)
	}

	if private != public {
		t.Errorf("private key gave %q, public half gave %q; want them equal", private, public)
	}
}

// RFC 9278 section 6 (MUST, promoted), read the other way: the specification's
// own URI, parsed, must yield SHA-256 and the RFC 7638 section 3.1 thumbprint of
// the key section 3 of that document presents.
//
// This is the one externally produced vector available for the parsing
// direction. A round trip through ThumbprintURI and back would agree with itself
// whatever prefix or separator the package chose; starting from the RFC's own
// string does not.
//
// rfc-req: RFC9278-S6-R01
func TestWorkedExampleURIParsesToTheRFCThumbprint(t *testing.T) {
	hash, thumbprint, err := jwk.ParseThumbprintURI(exampleURI)
	if err != nil {
		t.Fatalf("cannot parse the RFC's own URI: %v", err)
	}

	if hash != crypto.SHA256 {
		t.Errorf("got %s, want %s", hash, crypto.SHA256)
	}

	want, err := exampleKey(t).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot compute thumbprint: %v", err)
	}

	if !bytes.Equal(thumbprint, want) {
		t.Errorf("got  %x\nwant %x", thumbprint, want)
	}
}

// RFC 9278 section 4 (MUST): "JWK Thumbprint URIs with hash algorithm
// identifiers not found in this registry are not considered valid and
// applications will need to detect and handle this error, should it occur."
//
// Detection is the obligation, and it falls on the consumer, so it can only be
// tested against a parser. The identifiers below are chosen to be the ones a
// plausible implementation would let through: "sha-1" and "md5" are real
// registry entries for hashes this package will not use, "SHA-256" is Go's own
// spelling of an identifier that is registered under another, and "sha-256-128"
// is a registered truncated form whose digest width differs from the name it
// most resembles.
//
// rfc-req: RFC9278-S4-R02
func TestURIsNamingUnregisteredHashesAreDetected(t *testing.T) {
	const prefix = "urn:ietf:params:oauth:jwk-thumbprint"

	for _, name := range []string{"sha-1", "md5", "SHA-256", "sha-256-128", "sha256", ""} {
		uri := prefix + ":" + name + ":NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

		hash, thumbprint, err := jwk.ParseThumbprintURI(uri)
		if !errors.Is(err, jwk.ErrUnregisteredHashName) {
			t.Errorf("%q: got %v, want an error wrapping %v", name, err, jwk.ErrUnregisteredHashName)
		}

		if hash != 0 || thumbprint != nil {
			t.Errorf("%q: got (%v, %x) alongside the error, want nothing", name, hash, thumbprint)
		}
	}

	for _, name := range []string{"sha-256", "sha-384", "sha-512"} {
		uri, err := exampleKey(t).ThumbprintURI(hashByName(t, name))
		if err != nil {
			t.Fatalf("%s: cannot build URI: %v", name, err)
		}

		if _, _, err := jwk.ParseThumbprintURI(uri); err != nil {
			t.Errorf("%s: registered identifier refused: %v", name, err)
		}
	}
}

// RFC 9278 section 3 (MUST, promoted): "the prefix is followed by a hash
// algorithm identifier and a JWK Thumbprint value, each separated by a colon
// character to form a URI representing a JWK Thumbprint."
//
// The structure test above proves URIs are written in that shape; this one
// proves the shape is required when reading. Without it, "the prefix is
// followed by" would be satisfied by a parser that accepted anything and
// guessed.
//
// The last two cases assert an inference rather than the RFC's words: a
// thumbprint narrower or wider than the hash named cannot be a digest of that
// hash. The IR records it as inferred.
//
// rfc-req: RFC9278-S3-R02
func TestURIsNotShapedLikeTheRFCsAreRefused(t *testing.T) {
	const thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	for name, uri := range map[string]string{
		"a different URI scheme": "did:example:123456",
		"prefix misspelt":        "urn:ietf:params:oauth:jwk-thumbprints:sha-256:" + thumbprint,
		"prefix alone":           "urn:ietf:params:oauth:jwk-thumbprint",
		"no thumbprint":          "urn:ietf:params:oauth:jwk-thumbprint:sha-256",
		"no separators":          "urn:ietf:params:oauth:jwk-thumbprint sha-256 " + thumbprint,
		"a colon too many":       "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + thumbprint + ":x",
		"not base64url":          "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + strings.Replace(thumbprint, "-", "+", 1),
		"narrower than sha-512":  "urn:ietf:params:oauth:jwk-thumbprint:sha-512:" + thumbprint,
		"wider than sha-256":     "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + thumbprint + thumbprint,
	} {
		if _, _, err := jwk.ParseThumbprintURI(uri); !errors.Is(err, jwk.ErrMalformedThumbprintURI) {
			t.Errorf("%s: got %v, want an error wrapping %v", name, err, jwk.ErrMalformedThumbprintURI)
		}
	}
}

func hashByName(t *testing.T, name string) crypto.Hash {
	t.Helper()

	switch name {
	case "sha-256":
		return crypto.SHA256
	case "sha-384":
		return crypto.SHA384
	case "sha-512":
		return crypto.SHA512
	default:
		t.Fatalf("no hash named %q", name)

		return 0
	}
}

func exampleKey(t *testing.T) *jwk.Key {
	t.Helper()

	modulus, err := base64.RawURLEncoding.DecodeString(exampleModulus)
	if err != nil {
		t.Fatalf("cannot decode the example modulus: %v", err)
	}

	exponent, err := base64.RawURLEncoding.DecodeString(exampleExponent)
	if err != nil {
		t.Fatalf("cannot decode the example exponent: %v", err)
	}

	return jwk.NewKey(&rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(new(big.Int).SetBytes(exponent).Int64()),
	})
}
