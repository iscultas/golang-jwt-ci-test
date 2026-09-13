package jwk_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

const rsaThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

func thumbprintID(t *testing.T, key *jwk.Key) string {
	t.Helper()

	id, err := key.ThumbprintID(crypto.SHA256)
	if err != nil {
		t.Fatalf("cannot compute thumbprint: %v", err)
	}

	return id
}

func thumbprintOf(canonicalKey string) string {
	digest := sha256.Sum256([]byte(canonicalKey))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func TestThumbprintCanonicalForm(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		key          *jwk.Key
		canonicalKey string
	}{
		{
			"EllipticCurve",
			ellipticCurvePublicKey(t),
			`{"crv":"P-256","kty":"EC","x":"` + ellipticCurveX + `","y":"` + ellipticCurveY + `"}`,
		},
		{
			"Symmetric",
			symmetricKey(t),
			`{"k":"` + symmetricKeyMaterial + `","kty":"oct"}`,
		},
		{
			"EllipticCurveShortCoordinate",
			shortEllipticCurveKey(t),
			`{"crv":"P-256","kty":"EC","x":"` + shortEllipticCurveX + `","y":"` + shortEllipticCurveY + `"}`,
		},
		{
			"AKP",
			mldsaKey(t),
			`{"alg":"ML-DSA-44","kty":"AKP","pub":"` + mldsaPublicKeyValue(t) + `"}`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if id := thumbprintID(t, testCase.key); id != thumbprintOf(testCase.canonicalKey) {
				t.Errorf("got %s, want the thumbprint of %s", id, testCase.canonicalKey)
			}
		})
	}
}

func TestThumbprintsDiffer(t *testing.T) {
	thumbprints := make(map[string]string)

	for _, testCase := range []struct {
		name string
		key  *jwk.Key
	}{
		{"RSA", rsaKey(t)},
		{"EllipticCurve", ellipticCurvePublicKey(t)},
		{"EllipticCurveShortCoordinate", shortEllipticCurveKey(t)},
		{"Ed25519", ed25519Key(t)},
		{"Symmetric", symmetricKey(t)},
		{"AKP", mldsaKey(t)},
	} {
		id := thumbprintID(t, testCase.key)

		if previous, ok := thumbprints[id]; ok {
			t.Errorf("%s and %s share the thumbprint %s", testCase.name, previous, id)
		}

		thumbprints[id] = testCase.name
	}
}

func TestThumbprintNamesKey(t *testing.T) {
	publicKey := rsaKey(t).Public()

	namedKey := jwk.NewKey(publicKey.Material(), jwk.WithID(thumbprintID(t, publicKey)))

	selectedKey, err := jwk.NewKeySet(namedKey).Key(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.RS256(), rsaThumbprint)
	if err != nil {
		t.Fatalf("cannot select key: %v", err)
	}

	if selectedKey != namedKey {
		t.Error("got a different key than the one named by its thumbprint")
	}
}

func TestThumbprintOctets(t *testing.T) {
	thumbprint, err := rsaPublicKey(t).Thumbprint(crypto.SHA512)
	if err != nil {
		t.Fatalf("cannot compute thumbprint: %v", err)
	}

	if len(thumbprint) != crypto.SHA512.Size() {
		t.Errorf("got %d octets, want %d", len(thumbprint), crypto.SHA512.Size())
	}

	id, err := rsaPublicKey(t).ThumbprintID(crypto.SHA512)
	if err != nil {
		t.Fatalf("cannot compute thumbprint: %v", err)
	}

	if encodedThumbprint := base64.RawURLEncoding.EncodeToString(thumbprint); id != encodedThumbprint {
		t.Errorf("got %s, want %s", id, encodedThumbprint)
	}
}

func TestThumbprintUnavailableHash(t *testing.T) {
	if _, err := rsaPublicKey(t).Thumbprint(crypto.MD4); !errors.Is(err, jwk.ErrUnavailableHash) {
		t.Errorf("got error %v, want %v", err, jwk.ErrUnavailableHash)
	}

	if _, err := rsaPublicKey(t).ThumbprintID(crypto.MD4); !errors.Is(err, jwk.ErrUnavailableHash) {
		t.Errorf("got error %v, want %v", err, jwk.ErrUnavailableHash)
	}
}

func TestThumbprintUnsupportedKeyType(t *testing.T) {
	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(`{"kty":"bogus"}`), key); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	_, err := key.Thumbprint(crypto.SHA256)
	if !errors.Is(err, jwk.ErrUnsupportedKeyType) {
		t.Errorf("got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
	}
}

func TestThumbprintMalformedKey(t *testing.T) {
	_, err := oversizedEllipticCurveKey(t).Thumbprint(crypto.SHA256)
	if !errors.Is(err, jwk.ErrMalformedKey) {
		t.Errorf("got error %v, want %v", err, jwk.ErrMalformedKey)
	}
}

func TestParseThumbprintURIRoundTrip(t *testing.T) {
	key := ed25519Key(t)

	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		uri, err := key.ThumbprintURI(hash)
		if err != nil {
			t.Fatalf("%s: cannot build URI: %v", hash, err)
		}

		parsed, thumbprint, err := jwk.ParseThumbprintURI(uri)
		if err != nil {
			t.Fatalf("%s: cannot parse URI: %v", hash, err)
		}

		if parsed != hash {
			t.Errorf("%s: got %s", hash, parsed)
		}

		want, err := key.Thumbprint(hash)
		if err != nil {
			t.Fatalf("%s: cannot compute thumbprint: %v", hash, err)
		}

		if !bytes.Equal(thumbprint, want) {
			t.Errorf("%s: got %x, want %x", hash, thumbprint, want)
		}
	}
}

func TestParseMalformedThumbprintURI(t *testing.T) {
	for name, uri := range map[string]string{
		"empty":            "",
		"prefix truncated": "urn:ietf:params:oauth:jwk:sha-256:" + rsaThumbprint,
		"no hash name":     jwk.ThumbprintURIPrefix + ":",
		"empty thumbprint": jwk.ThumbprintURIPrefix + ":sha-256:",
		"padded":           jwk.ThumbprintURIPrefix + ":sha-256:" + rsaThumbprint + "=",
		"truncated digest": jwk.ThumbprintURIPrefix + ":sha-256:" + rsaThumbprint[:20],
	} {
		if _, _, err := jwk.ParseThumbprintURI(uri); !errors.Is(err, jwk.ErrMalformedThumbprintURI) {
			t.Errorf("%s: got %v, want %v", name, err, jwk.ErrMalformedThumbprintURI)
		}
	}
}
