package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

func exampleToken(options ...func(*jws.Signature)) string {
	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.ES256(), jwk.NewKey(material, jwk.WithID("2026-08")), options...),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	return serialized
}

func Example() {
	parts := strings.Split(
		exampleToken(jws.WithProtectedHeader(header.WithKeyID("2026-08"))), ".",
	)

	signature := new(jws.Signature)
	if err := signature.Unmarshal(parts[0], parts[2]); err != nil {
		panic(err)
	}

	fmt.Println(
		signature.ProtectedHeader.Algorithm,
		signature.ProtectedHeader.KeyID,
		signature.Header == nil,
		signature.String() == parts[2],
	)

	// Output:
	// ES256 2026-08 true true
}

func Example_encryptionAlgorithm() {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","enc":"A256GCM"}`))

	signature := new(jws.Signature)
	err := signature.Unmarshal(encoded, "")

	fmt.Println(errors.Is(err, jws.ErrEncryptionAlgorithm))

	// Output:
	// true
}

func ExampleSignature() {
	keySetURL, err := url.Parse("https://issuer.example/.well-known/jwks.json")
	if err != nil {
		panic(err)
	}

	signature := &jws.Signature{
		ProtectedHeader: new(header.Header),
		Signature:       []byte{1, 2, 3, 4},
	}

	jws.WithProtectedHeader(header.WithKeyID("2026-08"))(signature)
	jws.WithHeader(header.WithJWKSetURL(keySetURL))(signature)

	document, err := json.Marshal(signature)
	if err != nil {
		panic(err)
	}

	received := new(jws.Signature)
	if err := json.Unmarshal(document, received); err != nil {
		panic(err)
	}

	fmt.Println(received.ProtectedHeader.KeyID, received.Header.JWKSetURL, received.String())

	// Output:
	// 2026-08 https://issuer.example/.well-known/jwks.json AQIDBA
}

func ExampleSignature_Disjoint() {
	signature := &jws.Signature{ProtectedHeader: new(header.Header)}

	jws.WithProtectedHeader(header.WithKeyID("2026-08"))(signature)
	jws.WithHeader(header.WithKeyID("2026-09"))(signature)

	duplicate := signature.Disjoint()

	_, marshalled := json.Marshal(signature)

	fmt.Println(
		errors.Is(duplicate, jws.ErrDuplicateHeaderParameter),
		errors.Is(marshalled, jws.ErrDuplicateHeaderParameter),
	)

	// Output:
	// true true
}

func ExampleWithProtectedHeader() {
	certificateURL, err := url.Parse("https://issuer.example/certificates.pem")
	if err != nil {
		panic(err)
	}

	serialized := exampleToken(
		jws.WithProtectedHeader(header.WithKeyID("2026-08")),
		jws.WithHeader(header.WithX509URL(certificateURL)),
	)

	parts := strings.Split(serialized, ".")

	signature := new(jws.Signature)
	if err := signature.Unmarshal(parts[0], parts[2]); err != nil {
		panic(err)
	}

	fmt.Println(signature.ProtectedHeader.KeyID, signature.ProtectedHeader.X509URL)

	// Output:
	// 2026-08 <nil>
}

func ExampleWithHeader() {
	encoded := true

	signature := &jws.Signature{ProtectedHeader: new(header.Header)}
	jws.WithHeader()(signature)

	signature.Header.Base64URLEncodePayload = &encoded
	signature.Header.Critical = []string{header.UnencodedPayload}

	_, err := json.Marshal(signature)

	fmt.Println(errors.Is(err, jws.ErrUnprotectedUnencodedPayload))

	// Output:
	// true
}
