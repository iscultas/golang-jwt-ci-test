package jwk_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func exampleCertificate(key *ecdsa.PrivateKey) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "issuer.example"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return certificate
}

func exampleKey() *jwk.Key {
	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return jwk.NewKey(
		material,
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
		jwk.WithAlgorithm(jwa.ES256()),
		jwk.WithID("2026-08"),
	)
}

func ExampleKeySet() {
	signingKey := exampleKey()

	published, err := json.Marshal(jwk.NewKeySet(signingKey).Public())
	if err != nil {
		panic(err)
	}

	set := new(jwk.KeySet)
	if err := json.Unmarshal(published, set); err != nil {
		panic(err)
	}

	candidate, err := set.Key(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.ES256(), "2026-08")
	if err != nil {
		panic(err)
	}

	fmt.Println(candidate.Type(), candidate.ID(), candidate.IsPrivate())

	// Output:
	// EC 2026-08 false
}

func ExampleKey_Thumbprint() {
	signingKey := exampleKey()

	thumbprint, err := signingKey.ThumbprintID(crypto.SHA256)
	if err != nil {
		panic(err)
	}

	uri, err := signingKey.ThumbprintURI(crypto.SHA256)
	if err != nil {
		panic(err)
	}

	hash, digest, err := jwk.ParseThumbprintURI(uri)
	if err != nil {
		panic(err)
	}

	same, err := signingKey.Thumbprint(hash)
	if err != nil {
		panic(err)
	}

	fmt.Println(hash, len(thumbprint), bytes.Equal(digest, same))

	// Output:
	// SHA-256 43 true
}

func ExampleSourceFunc() {
	document := []byte(`{"keys":[]}`)

	keys := jwk.SourceFunc(func(_ context.Context) (*jwk.KeySet, error) {
		set := new(jwk.KeySet)
		if err := json.Unmarshal(document, set); err != nil {
			return nil, err
		}

		return set, nil
	})

	set, err := keys.Get(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println(len(set.Keys))

	// Output:
	// 0
}

func Example() {
	signingKey := exampleKey()

	document, err := json.Marshal(signingKey.Public())
	if err != nil {
		panic(err)
	}

	received := new(jwk.Key)
	if err := json.Unmarshal(document, received); err != nil {
		panic(err)
	}

	fmt.Println(received.Type(), received.ID(), received.Algorithm(), received.IsPrivate())

	// Output:
	// EC 2026-08 ES256 false
}

func ExampleNewKey() {
	ed25519PublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	for _, material := range []any{
		ecdsaKey,
		&rsaKey.PublicKey,
		ed25519PublicKey,
		[]byte("0123456789abcdef0123456789abcdef"),
	} {
		key := jwk.NewKey(material)

		fmt.Println(key.Type(), key.IsPrivate())
	}

	_, isECDSA := jwk.NewKey(ecdsaKey).Material().(*ecdsa.PrivateKey)

	symmetric := jwk.NewKey([]byte("0123456789abcdef0123456789abcdef")).Public()

	fmt.Println(isECDSA, symmetric == nil)

	// Output:
	// EC true
	// RSA false
	// OKP false
	// oct true
	// true true
}

func ExampleWithAlgorithm() {
	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	key := jwk.NewKey(
		material,
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Sign, jwk.Verify),
		jwk.WithAlgorithm(jwa.ES256()),
		jwk.WithID("2026-08"),
	)

	_, inconsistent := json.Marshal(jwk.NewKey(
		material,
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Decrypt),
	))

	_, duplicate := json.Marshal(jwk.NewKey(material, jwk.WithOperations(jwk.Sign, jwk.Sign)))

	fmt.Println(key.PublicKeyUse(), key.Operations(), key.Algorithm(), key.ID())
	fmt.Println(
		errors.Is(inconsistent, jwk.ErrInconsistentKeyUse),
		errors.Is(duplicate, jwk.ErrDuplicateKeyOperation),
	)

	// Output:
	// sig [sign verify] ES256 2026-08
	// true true
}

func ExampleKeySet_Candidates() {
	first := exampleKey()

	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	second := jwk.NewKey(
		material,
		jwk.WithPublicKeyUse(jwk.Signature),
		jwk.WithOperations(jwk.Verify),
		jwk.WithAlgorithm(jwa.ES256()),
	)

	set := jwk.NewKeySet(second.Public(), first.Public())

	candidates := set.Candidates(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.ES256(), "2026-08")

	for _, candidate := range candidates {
		fmt.Println(candidate.ID() == "2026-08")
	}

	_, none := set.Key(jwk.Encryption, []jwk.Operation{jwk.Decrypt}, jwa.ECDHES(), "")

	fmt.Println(errors.Is(none, jwk.ErrNoSuitableKey))

	// Output:
	// true
	// false
	// true
}

func ExampleKey_UnmarshalJSON() {
	document := []byte(`{
		"kty": "EC",
		"crv": "P-256",
		"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"kid": "2026-08"
	}`)

	key := new(jwk.Key)
	if err := json.Unmarshal(document, key); err != nil {
		panic(err)
	}

	incomplete := json.Unmarshal([]byte(`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}`), new(jwk.Key))

	var missing *jwk.MissingRequiredParameterError
	if !errors.As(incomplete, &missing) {
		panic(incomplete)
	}

	fmt.Println(key.Type(), key.ID(), key.IsPrivate())
	fmt.Println(missing.Parameter, missing)

	// Output:
	// EC 2026-08 false
	// y jwk: missing required parameter: y
}

func ExampleWithX509CertificateChain() {
	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	certificate := exampleCertificate(material)

	certificateURL, err := url.Parse("https://issuer.example/certificates.pem")
	if err != nil {
		panic(err)
	}

	thumbprint := sha256.Sum256(certificate.Raw)

	key := jwk.NewKey(
		material.Public(),
		jwk.WithX509CertificateChain([]*x509.Certificate{certificate}),
		jwk.WithX509URL(certificateURL),
		jwk.WithX509CertificateSHA256Thumbprint(base64.RawURLEncoding.EncodeToString(thumbprint[:])),
	)

	encoded := []string{base64.StdEncoding.EncodeToString(certificate.Raw)}

	matched := key.CheckCertificateChain(encoded)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	mismatched := jwk.NewKey(other.Public()).CheckCertificateChain(encoded)

	fmt.Println(len(key.X509CertificateChain()), key.X509URL(), key.X509CertificateSHA1Thumbprint() == "")
	fmt.Println(matched, errors.Is(mismatched, jwk.ErrCertificateKeyMismatch))

	// Output:
	// 1 https://issuer.example/certificates.pem true
	// <nil> true
}

func ExampleRefresher() {
	source := new(exampleRefresher)
	source.published.Store(jwk.NewKeySet(exampleKey().Public()))

	cached, err := source.Get(context.Background())
	if err != nil {
		panic(err)
	}

	source.published.Store(jwk.NewKeySet(exampleKey().Public(), exampleKey().Public()))

	refreshed, err := source.Refresh(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println(len(cached.Keys), len(refreshed.Keys))

	// Output:
	// 1 2
}

type exampleRefresher struct {
	published atomic.Pointer[jwk.KeySet]
	cached    atomic.Pointer[jwk.KeySet]
}

func (source *exampleRefresher) Get(ctx context.Context) (*jwk.KeySet, error) {
	if cached := source.cached.Load(); cached != nil {
		return cached, nil
	}

	return source.Refresh(ctx)
}

func (source *exampleRefresher) Refresh(context.Context) (*jwk.KeySet, error) {
	published := source.published.Load()
	source.cached.Store(published)

	return published, nil
}
