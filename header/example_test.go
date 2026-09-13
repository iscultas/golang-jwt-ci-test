package header_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func exampleKey() *ecdsa.PrivateKey {
	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return material
}

func exampleCertificate(key *ecdsa.PrivateKey) []byte {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "issuer.example"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	return certificate
}

func Example() {
	protected := &header.Header{Type: "JWT", Algorithm: jwa.ES256()}
	header.WithKeyID("2026-08")(protected)

	encoded, err := protected.Marshal()
	if err != nil {
		panic(err)
	}

	received := new(header.Header)
	if err := received.Unmarshal(encoded); err != nil {
		panic(err)
	}

	members, err := received.Members()
	if err != nil {
		panic(err)
	}

	empty := new(header.Header)

	fmt.Println(received.Algorithm, received.KeyID, received.Type)
	fmt.Println(strings.Join(members, " "))
	fmt.Println(empty.IsZero(), empty.String())

	// Output:
	// ES256 2026-08 JWT
	// alg kid typ
	// true e30
}

func ExampleWithJWK() {
	key := jwk.NewKey(exampleKey(), jwk.WithID("2026-08"))

	protected := &header.Header{Algorithm: jwa.ES256()}
	header.WithJWK(key.Public())(protected)

	encoded, err := protected.Marshal()
	if err != nil {
		panic(err)
	}

	received := new(header.Header)
	if err := received.Unmarshal(encoded); err != nil {
		panic(err)
	}

	fmt.Println(received.JWK.Type(), received.JWK.ID(), received.JWK.IsPrivate())

	// Output:
	// EC 2026-08 false
}

func ExampleWithJWKSetURL() {
	keySetURL, err := url.Parse("https://issuer.example/.well-known/jwks.json")
	if err != nil {
		panic(err)
	}

	protected := &header.Header{Algorithm: jwa.ES256()}
	header.WithJWKSetURL(keySetURL)(protected)
	header.WithKeyID("2026-08")(protected)

	members, err := protected.Members()
	if err != nil {
		panic(err)
	}

	fmt.Println(protected.JWKSetURL, protected.KeyID)
	fmt.Println(strings.Join(members, " "))

	// Output:
	// https://issuer.example/.well-known/jwks.json 2026-08
	// alg jku kid
}

func ExampleWithX509CertificateChain() {
	key := exampleKey()
	certificate := exampleCertificate(key)

	certificateURL, err := url.Parse("https://issuer.example/certificates.pem")
	if err != nil {
		panic(err)
	}

	sha1Thumbprint := sha1.Sum(certificate)
	sha256Thumbprint := sha256.Sum256(certificate)

	protected := &header.Header{Algorithm: jwa.ES256()}
	header.WithX509CertificateChain(base64.StdEncoding.EncodeToString(certificate))(protected)
	header.WithX509URL(certificateURL)(protected)
	header.WithX509CertificateSHA1Thumbprint(
		base64.RawURLEncoding.EncodeToString(sha1Thumbprint[:]),
	)(protected)
	header.WithX509CertificateSHA256Thumbprint(
		base64.RawURLEncoding.EncodeToString(sha256Thumbprint[:]),
	)(protected)

	members, err := protected.Members()
	if err != nil {
		panic(err)
	}

	if err := jwk.NewKey(key.Public()).CheckCertificateChain(protected.X509CertificateChain); err != nil {
		panic(err)
	}

	fmt.Println(len(protected.X509CertificateChain), protected.X509URL)
	fmt.Println(strings.Join(members, " "))

	// Output:
	// 1 https://issuer.example/certificates.pem
	// alg x5c x5t x5t#S256 x5u
}

func ExampleMembersIn() {
	raw := []byte(`{"alg":"ECDH-1PU","kid":"2026-08"}`)

	members, err := header.MembersIn(raw)
	if err != nil {
		panic(err)
	}

	decoded := new(header.Header)
	rejected := json.Unmarshal(raw, decoded)

	fmt.Println(strings.Join(members, " "), rejected != nil)

	// Output:
	// alg kid true
}

func ExampleHeader_Encoded() {
	original := &header.Header{Algorithm: jwa.ES256()}

	encoded, err := original.Marshal()
	if err != nil {
		panic(err)
	}

	received := new(header.Header)
	if err := received.Unmarshal(encoded); err != nil {
		panic(err)
	}

	received.KeyID = "2026-08"

	kept, err := received.Marshal()
	if err != nil {
		panic(err)
	}

	received.SetEncoded("")

	rewritten, err := received.Marshal()
	if err != nil {
		panic(err)
	}

	fmt.Println(received.Encoded() == "", kept == encoded, rewritten == encoded)

	// Output:
	// true true false
}

func ExampleHeader_KeyParameters() {
	protected := &header.Header{
		Algorithm:           jwa.PBES2HS256A128KW(),
		EncryptionAlgorithm: jwa.A128GCM(),
	}

	if err := protected.SetKeyParameters(&jwa.KeyParameters{
		PBES2SaltInput: []byte("0123456789abcdef"),
		PBES2Count:     10000,
	}); err != nil {
		panic(err)
	}

	encoded, err := protected.Marshal()
	if err != nil {
		panic(err)
	}

	received := new(header.Header)
	if err := received.Unmarshal(encoded); err != nil {
		panic(err)
	}

	parameters := received.KeyParameters()

	agreement := &header.Header{
		Algorithm:           jwa.ECDHES(),
		EncryptionAlgorithm: jwa.A128GCM(),
	}
	if err := agreement.SetKeyParameters(&jwa.KeyParameters{
		EphemeralPublicKey: exampleKey(),
	}); err != nil {
		panic(err)
	}

	fmt.Println(string(parameters.PBES2SaltInput), parameters.PBES2Count)
	fmt.Println(agreement.EphemeralPublicKey.IsPrivate())

	// Output:
	// 0123456789abcdef 10000
	// false
}

func ExampleHeader_UnmarshalJSON() {
	ephemeralKey, err := json.Marshal(jwk.NewKey(exampleKey()))
	if err != nil {
		panic(err)
	}

	document := fmt.Appendf(nil,
		`{"alg":"ECDH-ES","enc":"A128GCM","epk":%s}`, ephemeralKey,
	)

	received := new(header.Header)
	rejected := json.Unmarshal(document, received)

	fmt.Println(errors.Is(rejected, header.ErrPrivateEphemeralKey))

	// Output:
	// true
}
