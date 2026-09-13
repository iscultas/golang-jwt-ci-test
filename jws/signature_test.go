package jws_test

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jws"
)

func encode(json string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

const (
	encodedProtectedHeader = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
	encodedSignature       = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func TestUnmarshal(t *testing.T) {
	signature := new(jws.Signature)

	if err := signature.Unmarshal(encodedProtectedHeader, encodedSignature); err != nil {
		t.Fatalf("cannot decode signature: %v", err)
	}

	if signature.ProtectedHeader.Algorithm != jwa.HS256() {
		t.Errorf("got algorithm %v, want HS256", signature.ProtectedHeader.Algorithm)
	}

	if signature.ProtectedHeader.Type != "JWT" {
		t.Errorf("got type %q, want JWT", signature.ProtectedHeader.Type)
	}

	if signature.Header != nil {
		t.Errorf("got unprotected header %v, want none", signature.Header)
	}

	if reencodedSignature := signature.String(); reencodedSignature != encodedSignature {
		t.Errorf("got %s, want %s", reencodedSignature, encodedSignature)
	}
}

func TestUnmarshalingMalformedSignature(t *testing.T) {
	t.Run("Signature", func(t *testing.T) {
		if err := new(jws.Signature).Unmarshal(encodedProtectedHeader, "not base64!"); err == nil {
			t.Error("got no error, want one")
		}
	})

	t.Run("ProtectedHeader", func(t *testing.T) {
		if err := new(jws.Signature).Unmarshal("not base64!", encodedSignature); err == nil {
			t.Error("got no error, want one")
		}
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		err := new(jws.Signature).Unmarshal(encode(`{"alg":"ECDH-1PU"}`), encodedSignature)

		if !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
			t.Errorf("got error %v, want %v", err, jwa.ErrUnsupportedAlgorithm)
		}
	})
}

func unmarshalJSON(t *testing.T, protectedHeaderJSON, unprotectedHeaderJSON string) (*jws.Signature, error) {
	t.Helper()

	rawSignature, err := json.Marshal(
		map[string]any{
			"protected": encode(protectedHeaderJSON),
			"header":    jsontext.Value(unprotectedHeaderJSON),
			"signature": encodedSignature,
		},
	)
	if err != nil {
		t.Fatalf("cannot encode signature: %v", err)
	}

	signature := new(jws.Signature)

	return signature, json.Unmarshal(rawSignature, signature)
}

func TestUnmarshalingJSONDisjointHeaders(t *testing.T) {
	signature, err := unmarshalJSON(t, `{"alg":"HS256"}`, `{"kid":"2010-12-29"}`)
	if err != nil {
		t.Fatalf("cannot decode signature: %v", err)
	}

	if signature.ProtectedHeader.Algorithm != jwa.HS256() {
		t.Errorf("got algorithm %v, want HS256", signature.ProtectedHeader.Algorithm)
	}

	if signature.Header == nil {
		t.Fatal("got no unprotected header, want one")
	}

	if signature.Header.KeyID != "2010-12-29" {
		t.Errorf("got key ID %q, want 2010-12-29", signature.Header.KeyID)
	}
}

func TestMarshalJSON(t *testing.T) {
	signature := new(jws.Signature)
	if err := signature.Unmarshal(encodedProtectedHeader, encodedSignature); err != nil {
		t.Fatalf("cannot decode signature: %v", err)
	}

	signature.Header = &header.Header{KeyID: "2010-12-29"}

	encodedJSON, err := json.Marshal(signature)
	if err != nil {
		t.Fatalf("cannot encode signature: %v", err)
	}

	var rawSignature struct {
		ProtectedHeader string         `json:"protected"`
		Header          jsontext.Value `json:"header"`
		Signature       string         `json:"signature"`
	}
	if err := json.Unmarshal(encodedJSON, &rawSignature); err != nil {
		t.Fatalf("cannot decode signature: %v", err)
	}

	if rawSignature.ProtectedHeader != encodedProtectedHeader {
		t.Errorf("got protected header %s, want %s", rawSignature.ProtectedHeader, encodedProtectedHeader)
	}

	if rawSignature.Signature != encodedSignature {
		t.Errorf("got signature %s, want %s", rawSignature.Signature, encodedSignature)
	}

	if string(rawSignature.Header) != `{"kid":"2010-12-29"}` {
		t.Errorf("got unprotected header %s, want {\"kid\":\"2010-12-29\"}", rawSignature.Header)
	}
}

func TestWithHeaders(t *testing.T) {
	signature := &jws.Signature{ProtectedHeader: new(header.Header)}

	jws.WithProtectedHeader(header.WithKeyID("signing"))(signature)
	jws.WithHeader(header.WithX509CertificateSHA1Thumbprint("2010-12-29"))(signature)

	if signature.ProtectedHeader.KeyID != "signing" {
		t.Errorf("got protected key ID %q, want signing", signature.ProtectedHeader.KeyID)
	}

	if signature.Header.X509CertificateSHA1Thumbprint != "2010-12-29" {
		t.Errorf("got x5t %q, want 2010-12-29", signature.Header.X509CertificateSHA1Thumbprint)
	}
}
