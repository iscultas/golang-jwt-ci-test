package jwk_test

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func FuzzUnmarshalKey(f *testing.F) {
	f.Add(encodedRsaKey)
	f.Add(encodedRsaPublicKey)
	f.Add(encodedEllipticCurvePublicKey)
	f.Add(encodedShortEllipticCurveKey)
	f.Add(encodedSymmetricKey)
	f.Add(encodedEd25519Key)
	f.Add(encodedEd25519PublicKey)
	f.Add(encodedX25519Key)
	f.Add(encodedX25519PublicKey)
	f.Add(encodedMLDSAKey(f))
	f.Add(encodedMLDSAPublicKey(f))
	f.Add("{}")
	f.Add("null")
	f.Add("[]")
	f.Add(`{"kty":"EC"}`)
	f.Add(`{"kty":"unheard of"}`)
	f.Add(`{"kty":"AKP"}`)
	f.Add(`{"kty":"AKP","alg":"ML-DSA-44"}`)
	f.Add(`{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA"}`)
	f.Add(`{"kty":"AKP","alg":"ES256","pub":"AAAA"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","key_ops":["sign","sign"]}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","use":"sig","key_ops":["encrypt"]}`)
	f.Add(`{"kty":"oct","k":"AAAA","x5c":["AAAA"]}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","x5t#S256":"AAAA"}`)

	f.Fuzz(func(t *testing.T, document string) {
		key := new(jwk.Key)
		if err := json.Unmarshal([]byte(document), key); err != nil {
			return
		}

		_ = key.Type()
		_ = key.IsPrivate()
		_ = key.Material()
		_ = key.Public()
		_, _ = key.Thumbprint(crypto.SHA256)
		_, _ = key.ThumbprintURI(crypto.SHA256)

		thumbprint, err := key.ThumbprintID(crypto.SHA256)
		if err != nil {
			return
		}

		encoded, err := json.Marshal(key)
		if err != nil {
			return
		}

		decoded := new(jwk.Key)
		if err := json.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("a key this package wrote did not decode: %s: %v", encoded, err)
		}

		roundTripped, err := decoded.ThumbprintID(crypto.SHA256)
		if err != nil {
			t.Fatalf("cannot compute the thumbprint of a round-tripped key %s: %v", encoded, err)
		}

		if roundTripped != thumbprint {
			t.Errorf("the thumbprint changed across a round trip: %q then %q", thumbprint, roundTripped)
		}
	})
}

func FuzzUnmarshalKeySet(f *testing.F) {
	f.Add(`{"keys":[]}`)
	f.Add(`{"keys":[` + encodedRsaKey + `]}`)
	f.Add(`{"keys":[` + encodedSymmetricKey + `,` + encodedEllipticCurvePublicKey + `]}`)
	f.Add(`{"keys":[{"kty":"unheard of"},` + encodedEd25519PublicKey + `]}`)
	f.Add(`{"keys":[null]}`)
	f.Add(`{"keys":null}`)
	f.Add(`{"keys":{}}`)
	f.Add("{}")
	f.Add("null")
	f.Add("[]")

	f.Fuzz(func(t *testing.T, document string) {
		keySet := new(jwk.KeySet)
		if err := json.Unmarshal([]byte(document), keySet); err != nil {
			return
		}

		for _, key := range keySet.Keys {
			if key == nil {
				t.Fatal("a decoded set holds a nil key")
			}

			if key.Material() == nil {
				t.Errorf("a decoded set kept a key holding no material")
			}
		}

		public := keySet.Public()

		if len(public.Keys) > len(keySet.Keys) {
			t.Errorf("the public set holds %d keys, more than the %d it came from", len(public.Keys), len(keySet.Keys))
		}

		for _, key := range public.Keys {
			if key.IsPrivate() {
				t.Errorf("the public set holds a private key")
			}
		}

		_ = keySet.Candidates(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.ES256(), "")
		_, _ = json.Marshal(keySet)
		_, _ = json.Marshal(public)
	})
}

func FuzzCheckCertificateChain(f *testing.F) {
	privateKey := generateKey(f)
	issuerKey := generateKey(f)

	issuer := issue(f, issuerKey, issuerKey, nil, x509.KeyUsageCertSign)
	leaf := issue(f, privateKey, issuerKey, issuer, x509.KeyUsageDigitalSignature)

	encode := func(certificate *x509.Certificate) string {
		return base64.StdEncoding.EncodeToString(certificate.Raw)
	}

	encodedLeaf, encodedIssuer := encode(leaf), encode(issuer)

	f.Add(encodedLeaf)
	f.Add(encodedLeaf + "." + encodedIssuer)
	f.Add(encodedIssuer + "." + encodedLeaf)
	f.Add(encodedLeaf[:len(encodedLeaf)/2])
	f.Add(base64.RawURLEncoding.EncodeToString(leaf.Raw))
	f.Add(strings.TrimSuffix(strings.Repeat(encodedLeaf+".", 10), "."))

	for _, length := range []int{3, 4, 5} {
		f.Add(strings.TrimSuffix(strings.Repeat(encodedLeaf+".", length), "."))
		f.Add(strings.TrimSuffix(strings.Repeat(encodedLeaf+"."+encodedIssuer+".", length), "."))
	}

	f.Add("")
	f.Add(".")
	f.Add("....")

	key := jwk.NewKey(&privateKey.PublicKey)

	f.Fuzz(func(t *testing.T, chain string) {
		var entries []string
		if chain != "" {
			entries = strings.Split(chain, ".")
		}

		_ = key.CheckCertificateChain(entries)
	})
}

func FuzzParseThumbprintURI(f *testing.F) {
	key := jwk.NewKey(&generateKey(f).PublicKey)

	uri, err := key.ThumbprintURI(crypto.SHA256)
	if err != nil {
		f.Fatalf("cannot build a thumbprint URI: %v", err)
	}

	prefix := jwk.ThumbprintURIPrefix + ":"

	f.Add(uri)
	f.Add(prefix + "sha-256:AAAA")
	f.Add(prefix + "sha-256:")
	f.Add(prefix + "sha-1:AAAA")
	f.Add(prefix + "unheard-of:AAAA")
	f.Add(prefix + "sha-256")
	f.Add(prefix)
	f.Add("")
	f.Add(":::")

	f.Fuzz(func(t *testing.T, raw string) {
		hash, thumbprint, err := jwk.ParseThumbprintURI(raw)
		if err != nil {
			return
		}

		if len(thumbprint) != hash.Size() {
			t.Errorf(
				"%q parsed to a %d-octet thumbprint for %s, which produces %d",
				raw, len(thumbprint), hash, hash.Size(),
			)
		}
	})
}
