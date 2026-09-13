package jwt_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func encodeSegment(data string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

func handAssembled(t testing.TB, privateKey *ecdsa.PrivateKey, protectedHeader, payload string) string {
	t.Helper()

	unsigned := encodeSegment(protectedHeader) + "." + encodeSegment(payload)

	signature, err := jwa.ES256().Sign([]byte(unsigned), privateKey)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func issuedCertificateChain(t testing.TB, privateKey *ecdsa.PrivateKey) (leaf, issuer string) {
	t.Helper()

	issuerKey := generateKey(t)

	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "jwt fuzz issuer"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	issuerDER, err := x509.CreateCertificate(
		rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey,
	)
	if err != nil {
		t.Fatalf("cannot create the issuer certificate: %v", err)
	}

	issuerCertificate, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("cannot parse the issuer certificate: %v", err)
	}

	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		&x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "jwt fuzz leaf"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
		},
		issuerCertificate, &privateKey.PublicKey, issuerKey,
	)
	if err != nil {
		t.Fatalf("cannot create the leaf certificate: %v", err)
	}

	return base64.StdEncoding.EncodeToString(leafDER), base64.StdEncoding.EncodeToString(issuerDER)
}

func acceptAnyKey(t *testing.T, shown *int) jwt.HeaderKeyPolicy {
	t.Helper()

	return func(key *jwk.Key, _ *header.Header) error {
		*shown++

		if key.Type() == jwk.OctetSequence {
			t.Errorf("a policy was shown symmetric material")
		}

		if key.IsPrivate() {
			t.Errorf("a policy was shown private material")
		}

		return nil
	}
}

func FuzzUnmarshal(f *testing.F) {
	f.Add(signedToken)
	f.Add("")
	f.Add("not.a.token")
	f.Add(`{"payload":"eyJpc3MiOiJqb2UifQ"}`)
	f.Add(`{"payload":"eyJpc3MiOiJqb2UifQ","protected":"eyJhbGciOiJIUzI1NiJ9","signature":""}`)
	f.Add(`{"payload":"eyJpc3MiOiJqb2UifQ","signatures":[null]}`)

	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0....")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwiY3R5IjoiSldUIn0....")
	f.Add("a.b.c.d.e")

	f.Fuzz(func(t *testing.T, encodedToken string) {
		keySet := jwk.NewKeySet(key(t, symmetricKeyMaterial))

		if token, err := jwt.Unmarshal(encodedToken); err == nil {
			_ = token.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig)
			_ = token.Decrypt(t.Context(), keySet, jwt.DefaultDecryptionConfig)
			_, _ = token.Marshal()
			_, _ = json.Marshal(token)
		}

		decodedToken := new(jwt.Token)
		if err := json.Unmarshal([]byte(encodedToken), decodedToken); err == nil {
			_ = decodedToken.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig)
			_, _ = json.Marshal(decodedToken)
		}
	})
}

func FuzzHeaderJWK(f *testing.F) {
	privateKey := generateKey(f)

	published, err := json.Marshal(jwk.NewKey(privateKey.Public()))
	if err != nil {
		f.Fatalf("cannot encode the signing key: %v", err)
	}

	f.Add(string(published))
	f.Add("{}")
	f.Add("null")
	f.Add("[]")
	f.Add(`"a string"`)
	f.Add(`{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"","y":""}`)
	f.Add(`{"kty":"EC","crv":"P-256"}`)
	f.Add(`{"kty":"RSA","n":"","e":""}`)
	f.Add(`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","d":"AAAA"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","use":"enc"}`)

	f.Fuzz(func(t *testing.T, embeddedKey string) {
		encodedToken := handAssembled(
			t, privateKey, fmt.Sprintf(`{"alg":"ES256","jwk":%s}`, embeddedKey), `{"iss":"joe"}`,
		)

		token, err := jwt.Unmarshal(encodedToken)
		if err != nil {
			return
		}

		shown := 0
		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(acceptAnyKey(t, &shown)))

		_ = token.Verify(t.Context(), nil, config)
		_ = token.Verify(t.Context(), jwk.NewKeySet(jwk.NewKey(privateKey.Public())), config)
		_, _ = token.Marshal()
		_, _ = json.Marshal(token)
	})
}

func FuzzHeaderCertificateChain(f *testing.F) {
	privateKey := generateKey(f)
	leaf, issuer := issuedCertificateChain(f, privateKey)

	leafDER, err := base64.StdEncoding.DecodeString(leaf)
	if err != nil {
		f.Fatalf("cannot decode the leaf certificate: %v", err)
	}

	leafDigest := sha256.Sum256(leafDER)
	leafThumbprint := base64.RawURLEncoding.EncodeToString(leafDigest[:])

	f.Add(leaf, "")
	f.Add(leaf, leafThumbprint)
	f.Add(leaf, "not a thumbprint")
	f.Add(leaf+"."+issuer, "")
	f.Add(issuer+"."+leaf, "")
	f.Add(leaf[:len(leaf)/2], "")
	f.Add(base64.RawURLEncoding.EncodeToString(leafDER), "")
	f.Add(strings.TrimSuffix(strings.Repeat(leaf+".", 10), "."), "")
	f.Add("", "")
	f.Add(".", "")

	for _, length := range []int{3, 4, 5} {
		f.Add(strings.TrimSuffix(strings.Repeat(leaf+".", length), "."), "")
		f.Add(strings.TrimSuffix(strings.Repeat(leaf+"."+issuer+".", length), "."), "")
	}

	f.Fuzz(func(t *testing.T, chain, thumbprint string) {
		protectedHeader := map[string]any{"alg": "ES256"}

		if chain != "" {
			protectedHeader["x5c"] = strings.Split(chain, ".")
		}

		if thumbprint != "" {
			protectedHeader["x5t#S256"] = thumbprint
		}

		encodedHeader, err := json.Marshal(protectedHeader)
		if err != nil {
			return
		}

		encodedToken := handAssembled(t, privateKey, string(encodedHeader), `{"iss":"joe"}`)

		token, err := jwt.Unmarshal(encodedToken)
		if err != nil {
			return
		}

		shown := 0
		config := jwt.NewVerificationConfig(jwt.WithHeaderKey(acceptAnyKey(t, &shown)))

		_ = token.Verify(t.Context(), nil, config)
		_, _ = token.Marshal()
		_, _ = json.Marshal(token)
	})
}

func FuzzConfirmation(f *testing.F) {
	privateKey := generateKey(f)

	published, err := json.Marshal(jwk.NewKey(privateKey.Public()))
	if err != nil {
		f.Fatalf("cannot encode the signing key: %v", err)
	}

	f.Add(`{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}`)
	f.Add(fmt.Sprintf(`{"jwk":%s}`, published))
	f.Add(fmt.Sprintf(`{"jwk":%s,"jwe":"a.b.c.d.e"}`, published))
	f.Add(`{"jku":"https://example.com/keys.jwks","kid":"one"}`)
	f.Add(`{"jwe":"a.b.c.d.e","jku":"https://example.com/keys.jwks"}`)
	f.Add(`{"kid":"one"}`)
	f.Add("{}")
	f.Add("null")
	f.Add("[]")
	f.Add(`"a string"`)
	f.Add("0")
	f.Add(`{"jwk":"not an object"}`)
	f.Add(`{"jwk":{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`)
	f.Add(`{"jku":":"}`)

	f.Fuzz(func(t *testing.T, claim string) {
		encodedToken := handAssembled(
			t, privateKey, `{"alg":"ES256"}`,
			fmt.Sprintf(`{"iss":"joe","sub":"presenter","cnf":%s}`, claim),
		)

		token, err := jwt.Unmarshal(encodedToken)
		if err != nil {
			return
		}

		confirmation, err := token.Confirmation()
		if err != nil || confirmation == nil {
			return
		}

		named := 0

		for _, present := range []bool{
			confirmation.JWK != nil,
			confirmation.EncryptedKey != "",
			confirmation.KeySetURL != nil,
		} {
			if present {
				named++
			}
		}

		if named > 1 {
			t.Errorf("cnf named %d keys in %q, want at most one", named, claim)
		}

		_, _ = json.Marshal(token)
	})
}
