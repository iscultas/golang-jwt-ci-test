package header_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/url"
	"reflect"
	"slices"
	"testing"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func encode(headerJSON string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
}

func TestUnmarshalingHeaderWithoutCriticalParameters(t *testing.T) {
	decodedHeader := new(header.Header)

	if err := decodedHeader.Unmarshal(encode(`{"typ":"JWT","alg":"HS256"}`)); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	if decodedHeader.Algorithm.String() != "HS256" {
		t.Errorf("got algorithm %s, want HS256", decodedHeader.Algorithm)
	}
}

func TestMarshalingEmptyCriticalParameters(t *testing.T) {
	encodedHeader, err := json.Marshal(&header.Header{Algorithm: jwa.HS256(), Critical: []string{}})
	if err != nil {
		t.Fatalf("cannot encode header: %v", err)
	}

	if string(encodedHeader) != `{"alg":"HS256"}` {
		t.Errorf("got %s, want a header carrying no crit member", encodedHeader)
	}
}

func TestUnmarshalingOmittedURLs(t *testing.T) {
	decodedHeader := new(header.Header)

	if err := decodedHeader.Unmarshal(encode(`{"alg":"HS256","kid":"2010-12-29"}`)); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	if decodedHeader.JWKSetURL != nil {
		t.Errorf("got jku %v, want none", decodedHeader.JWKSetURL)
	}

	if decodedHeader.X509URL != nil {
		t.Errorf("got x5u %v, want none", decodedHeader.X509URL)
	}
}

func TestUnmarshalingMalformedURLs(t *testing.T) {
	for name, headerJSON := range map[string]string{
		"JWKSetURL": `{"alg":"HS256","jku":"://example.com"}`,
		"X509URL":   `{"alg":"HS256","x5u":"http://a b.com"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := new(header.Header).Unmarshal(encode(headerJSON)); err == nil {
				t.Error("got no error, want a URL parse error")
			}
		})
	}
}

func TestUnmarshalingUnsupportedAlgorithm(t *testing.T) {
	err := new(header.Header).Unmarshal(encode(`{"alg":"ECDH-1PU"}`))

	if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got error %v, want %v", err, jwa.ErrUnsupportedAlgorithm)
	}
}

func TestUnmarshalingHeaderWithoutAlgorithm(t *testing.T) {
	decodedHeader := new(header.Header)

	if err := decodedHeader.Unmarshal(encode(`{"kid":"2010-12-29"}`)); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	if decodedHeader.Algorithm != nil {
		t.Errorf("got algorithm %v, want none", decodedHeader.Algorithm)
	}

	if decodedHeader.KeyID != "2010-12-29" {
		t.Errorf("got key ID %q, want 2010-12-29", decodedHeader.KeyID)
	}
}

func TestMarshalingOmitsAbsentAlgorithm(t *testing.T) {
	headerJSON, err := json.Marshal(&header.Header{KeyID: "2010-12-29"})
	if err != nil {
		t.Fatalf("cannot encode header: %v", err)
	}

	if string(headerJSON) != `{"kid":"2010-12-29"}` {
		t.Errorf(`got %s, want {"kid":"2010-12-29"}`, headerJSON)
	}
}

func TestRoundTrip(t *testing.T) {
	headerJSON := `{` +
		`"typ":"JWT",` +
		`"cty":"example",` +
		`"alg":"HS256",` +
		`"jku":"https://example.com/keys",` +
		`"kid":"2010-12-29",` +
		`"x5u":"https://example.com/certificates",` +
		`"x5c":["MIIBstub","MIIBrootca"],` +
		`"x5t":"thumbprint",` +
		`"x5t#S256":"sha256thumbprint"` +
		`}`

	decodedHeader := new(header.Header)
	if err := json.Unmarshal([]byte(headerJSON), decodedHeader); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	if decodedHeader.Type != "JWT" {
		t.Errorf("got type %q, want JWT", decodedHeader.Type)
	}

	if decodedHeader.ContentType != "example" {
		t.Errorf("got content type %q, want example", decodedHeader.ContentType)
	}

	if decodedHeader.Algorithm != jwa.HS256() {
		t.Errorf("got algorithm %v, want HS256", decodedHeader.Algorithm)
	}

	if got := decodedHeader.X509CertificateChain; !slices.Equal(got, []string{"MIIBstub", "MIIBrootca"}) {
		t.Errorf("got certificate chain %v, want [MIIBstub MIIBrootca]", got)
	}

	if decodedHeader.X509CertificateSHA1Thumbprint != "thumbprint" {
		t.Errorf("got x5t %q, want thumbprint", decodedHeader.X509CertificateSHA1Thumbprint)
	}

	if decodedHeader.X509CertificateSHA256Thumbprint != "sha256thumbprint" {
		t.Errorf("got x5t#S256 %q, want sha256thumbprint", decodedHeader.X509CertificateSHA256Thumbprint)
	}

	if decodedHeader.JWKSetURL == nil || decodedHeader.JWKSetURL.String() != "https://example.com/keys" {
		t.Errorf("got jku %v, want https://example.com/keys", decodedHeader.JWKSetURL)
	}

	if decodedHeader.X509URL == nil || decodedHeader.X509URL.String() != "https://example.com/certificates" {
		t.Errorf("got x5u %v, want https://example.com/certificates", decodedHeader.X509URL)
	}

	reencodedHeader, err := json.Marshal(decodedHeader)
	if err != nil {
		t.Fatalf("cannot encode header: %v", err)
	}

	var original, reencoded map[string]any
	if err := json.Unmarshal([]byte(headerJSON), &original); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}
	if err := json.Unmarshal(reencodedHeader, &reencoded); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	if !reflect.DeepEqual(original, reencoded) {
		t.Errorf("got %s, want %s", reencodedHeader, headerJSON)
	}
}

func TestMarshalingPreservesEncoding(t *testing.T) {
	encodedHeader := encode(`{"alg":"HS256","typ":"JWT"}`)

	decodedHeader := new(header.Header)
	if err := decodedHeader.Unmarshal(encodedHeader); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	reencodedHeader, err := decodedHeader.Marshal()
	if err != nil {
		t.Fatalf("cannot encode header: %v", err)
	}

	if reencodedHeader != encodedHeader {
		t.Errorf("got %s, want %s", reencodedHeader, encodedHeader)
	}
}

func TestStringPanicsWhereMarshalFails(t *testing.T) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("got no panic, want one")
		}

		err, isError := recovered.(error)
		if !isError || !errors.Is(err, header.ErrUnsupportedCriticalParameter) {
			t.Errorf("got panic %v, want %v", recovered, header.ErrUnsupportedCriticalParameter)
		}
	}()

	_ = (&header.Header{Critical: []string{"http://example.invalid/unsupported"}}).String()
}

func TestOptionsWriteTheirParameters(t *testing.T) {
	jwkSetURL, err := url.Parse("https://example.com/keys")
	if err != nil {
		t.Fatalf("cannot parse url: %v", err)
	}

	x509URL, err := url.Parse("https://example.com/certificates")
	if err != nil {
		t.Fatalf("cannot parse url: %v", err)
	}

	constructedHeader := new(header.Header)
	for _, option := range []func(*header.Header){
		header.WithJWKSetURL(jwkSetURL),
		header.WithKeyID("2010-12-29"),
		header.WithX509URL(x509URL),
		header.WithX509CertificateChain("MIIBstub", "MIIBrootca"),
		header.WithX509CertificateSHA1Thumbprint("thumbprint"),
		header.WithX509CertificateSHA256Thumbprint("sha256thumbprint"),
	} {
		option(constructedHeader)
	}

	encodedHeader, err := constructedHeader.Marshal()
	if err != nil {
		t.Fatalf("cannot encode header: %v", err)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	var members map[string]any
	if err := json.Unmarshal(headerJSON, &members); err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	want := map[string]any{
		"jku":      "https://example.com/keys",
		"kid":      "2010-12-29",
		"x5u":      "https://example.com/certificates",
		"x5c":      []any{"MIIBstub", "MIIBrootca"},
		"x5t":      "thumbprint",
		"x5t#S256": "sha256thumbprint",
	}

	if !reflect.DeepEqual(members, want) {
		t.Errorf("got %v, want %v", members, want)
	}
}

func TestMarshalAgreesWithMarshalJSON(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	certificateThumbprint := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

	for name, subject := range map[string]*header.Header{
		"the algorithm only": {Algorithm: jwa.HS256()},
		"a full JWS header": {
			Algorithm:                       jwa.ES256(),
			Type:                            "JWT",
			ContentType:                     "JWT",
			KeyID:                           "the key that signs",
			X509CertificateSHA256Thumbprint: certificateThumbprint,
		},
		"a jwk parameter": {Algorithm: jwa.ES256(), JWK: jwk.NewKey(&key.PublicKey)},
		"a jwk parameter and a key id": {
			Algorithm: jwa.ES256(),
			JWK:       jwk.NewKey(&key.PublicKey),
			KeyID:     "the key that signs",
		},
	} {
		t.Run(name, func(t *testing.T) {
			headerJSON, err := subject.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}

			encodedHeader, err := subject.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			decoded, err := base64.RawURLEncoding.Strict().DecodeString(encodedHeader)
			if err != nil {
				t.Fatalf("the text of Marshal does not decode: %v", err)
			}

			if !bytes.Equal(decoded, headerJSON) {
				t.Errorf("Marshal wrote %s, MarshalJSON wrote %s", decoded, headerJSON)
			}
		})
	}
}

func TestMarshalKeepsTheCriticalParameterChecks(t *testing.T) {
	base64URLEncodePayload := false

	for name, subject := range map[string]*header.Header{
		"an unsupported critical parameter": {Algorithm: jwa.HS256(), Critical: []string{"exp"}},
		"a critical parameter two times": {
			Algorithm:              jwa.HS256(),
			Critical:               []string{"b64", "b64"},
			Base64URLEncodePayload: &base64URLEncodePayload,
		},
		"an unencoded payload": {
			Algorithm:              jwa.HS256(),
			Critical:               []string{"b64"},
			Base64URLEncodePayload: &base64URLEncodePayload,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := subject.MarshalJSON(); err == nil {
				t.Fatal("MarshalJSON gave no error, so this header does not cover the check")
			}

			encodedHeader, err := subject.Marshal()
			if err == nil {
				t.Errorf("Marshal gave %q, want an error", encodedHeader)
			}
		})
	}
}
