package jwt_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

var exampleSecret = []byte("0123456789abcdef0123456789abcdef")

func exampleECDSAKey(curve elliptic.Curve) *jwk.Key {
	material, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	return jwk.NewKey(material, jwk.WithID("2026-08"))
}

func Example() {
	signingKey := jwk.NewKey(exampleSecret, jwk.WithID("2026-08"))

	expiration := time.Now().Add(time.Hour)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithAudience("https://api.example"),
		jwt.WithExpirationTime(&expiration),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwt.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.HS256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
		jwt.WithExpectedAudience("https://api.example"),
	)

	if err := received.Verify(context.Background(), jwk.NewKeySet(signingKey), config); err != nil {
		panic(err)
	}

	fmt.Println(received.Subject(), received.Verified())

	// Output:
	// alice true
}

func ExampleWithPrivateClaim() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithPrivateClaim("scope", "read write"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	scope, present, err := token.Claim[string]("scope")
	if err != nil {
		panic(err)
	}

	_, absent, err := token.Claim[string]("act")
	if err != nil {
		panic(err)
	}

	if err := token.RequireClaims("iss", "sub", "scope"); err != nil {
		panic(err)
	}

	fmt.Println(scope, present, absent)

	// Output:
	// read write true false
}

func ExampleWithClock() {
	signingKey := jwk.NewKey(exampleSecret)

	expiration := time.Unix(2000, 0)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithExpirationTime(&expiration),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	keySet := jwk.NewKeySet(signingKey)

	before := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithClock(func() time.Time { return time.Unix(1000, 0) }),
	))

	after := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithClock(func() time.Time { return time.Unix(3000, 0) }),
	))

	fmt.Println(before, errors.Is(after, jwt.ErrExpired))

	// Output:
	// <nil> true
}

func ExampleWithExpectedAudience() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithAudience("https://api.example"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	keySet := jwk.NewKeySet(signingKey)

	accepted := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithExpectedAudience("https://reports.example", "https://api.example"),
	))

	refused := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithExpectedAudience("https://other.example"),
	))

	fmt.Println(accepted, errors.Is(refused, jwt.ErrUnexpectedAudience))

	// Output:
	// <nil> true
}

func ExampleWithEncryption() {
	material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	recipient := jwk.NewKey(
		material,
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.DeriveKey),
	)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithEncryption(jwa.ECDHESA256KW(), jwa.A256GCM(), recipient.Public()),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwt.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	fmt.Println(received.Subject() == "", received.Verified())

	config := jwt.NewDecryptionConfig(
		jwt.WithKeyManagementAlgorithms(jwa.ECDHESA256KW()),
		jwt.WithContentEncryptionAlgorithms(jwa.A256GCM()),
	)

	if err := received.Decrypt(context.Background(), jwk.NewKeySet(recipient), config); err != nil {
		panic(err)
	}

	fmt.Println(received.Subject(), received.Verified())

	// Output:
	// true false
	// alice true
}

func ExampleWithEncryption_nested() {
	signingKey := exampleECDSAKey(elliptic.P256())

	encryptionKey := jwk.NewKey(
		make([]byte, 32),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.Encrypt, jwk.Decrypt),
	)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithSignature(jwa.ES256(), signingKey),
		jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), encryptionKey),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwt.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	config := jwt.NewDecryptionConfig(
		jwt.WithRequiredNestedToken(),
		jwt.WithVerification(
			jwt.WithAlgorithms(jwa.ES256()),
			jwt.WithExpectedIssuer("https://issuer.example"),
		),
	)

	if err := received.Decrypt(context.Background(),
		jwk.NewKeySet(encryptionKey, signingKey.Public()), config,
	); err != nil {
		panic(err)
	}

	fmt.Println(received.Subject(), received.Verified())

	// Output:
	// alice true
}

func ExampleToken_MarshalJSON() {
	firstKey := exampleECDSAKey(elliptic.P256())
	secondKey := exampleECDSAKey(elliptic.P384())

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.ES256(), firstKey),
		jwt.WithSignature(jwa.ES384(), secondKey),
	)
	if err != nil {
		panic(err)
	}

	if _, err := token.Marshal(); !errors.Is(err, jwt.ErrMultipleSignatures) {
		panic("the compact serialization accepted two signatures")
	}

	serialized, err := json.Marshal(token)
	if err != nil {
		panic(err)
	}

	received := new(jwt.Token)
	if err := json.Unmarshal(serialized, received); err != nil {
		panic(err)
	}

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES256(), jwa.ES384()),
		jwt.WithAllSignatures(),
	)

	if err := received.Verify(context.Background(),
		jwk.NewKeySet(firstKey.Public(), secondKey.Public()), config,
	); err != nil {
		panic(err)
	}

	fmt.Println(len(received.Signatures()))

	// Output:
	// 2
}

func ExampleWithRule() {
	errNotAnAccessToken := errors.New("profile: not an access token")

	issuance := func(token *jwt.Token) error {
		return token.RequireClaims("iss", "sub", "client_id")
	}

	verification := func(_ context.Context, token *jwt.Token, _ jwt.VerificationConfig) error {
		for _, signature := range token.Signatures() {
			if signature.ProtectedHeader.Type != "at+jwt" {
				return fmt.Errorf("%w: typ is %q", errNotAnAccessToken, signature.ProtectedHeader.Type)
			}
		}

		return token.RequireClaims("client_id")
	}

	signingKey := exampleECDSAKey(elliptic.P256())

	token, err := jwt.NewToken(
		jwt.WithType("at+jwt"),
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithPrivateClaim("client_id", "s6BhdRkqt3"),
		jwt.WithSignature(
			jwa.ES256(), signingKey,
			jws.WithProtectedHeader(header.WithKeyID(signingKey.ID())),
		),
		jwt.WithIssuanceRule(issuance),
	)
	if err != nil {
		panic(err)
	}

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
		jwt.WithExpectedType("at+jwt"),
		jwt.WithLeeway(30*time.Second),
		jwt.WithRule(verification),
	)

	if err := token.Verify(context.Background(), jwk.NewKeySet(signingKey.Public()), config); err != nil {
		panic(err)
	}

	fmt.Println(token.Subject())

	// Output:
	// alice
}

func ExampleUnmarshal() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwt.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	issuer := received.Issuer()

	if err := received.Verify(context.Background(), jwk.NewKeySet(signingKey),
		jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.HS256())),
	); err != nil {
		panic(err)
	}

	_, malformed := jwt.Unmarshal("not a token")

	fmt.Println(issuer, received.Verified(), errors.Is(malformed, jwt.ErrMalformedToken))

	// Output:
	// https://issuer.example true true
}

func ExampleToken_Marshal() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	two, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.ES256(), exampleECDSAKey(elliptic.P256())),
		jwt.WithSignature(jwa.ES384(), exampleECDSAKey(elliptic.P384())),
	)
	if err != nil {
		panic(err)
	}

	_, multiple := two.Marshal()

	fmt.Println(strings.Count(serialized, ".") == 2, token.String() == serialized)
	fmt.Println(errors.Is(multiple, jwt.ErrMultipleSignatures))

	// Output:
	// true true
	// true
}

func ExampleWithIssuer() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithType("at+jwt"),
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithAudience("https://api.example", "https://reports.example"),
		jwt.WithID("Iq8SbJ3Ir1"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(token.Issuer(), token.Subject(), token.ID(), token.Type())
	fmt.Println(token.Audience())

	// Output:
	// https://issuer.example alice Iq8SbJ3Ir1 at+jwt
	// [https://api.example https://reports.example]
}

func ExampleWithNotBefore() {
	signingKey := jwk.NewKey(exampleSecret)

	issuedAt := time.Unix(1000, 0)
	notBefore := time.Unix(2000, 0)
	expiration := time.Unix(3000, 0)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithIssuedAt(&issuedAt),
		jwt.WithNotBefore(&notBefore),
		jwt.WithExpirationTime(&expiration),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	keySet := jwk.NewKeySet(signingKey)

	at := func(seconds int64) error {
		return token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
			jwt.WithClock(func() time.Time { return time.Unix(seconds, 0) }),
		))
	}

	fmt.Println(token.IssuedAt().Unix(), token.NotBefore().Unix(), token.ExpirationTime().Unix())
	fmt.Println(
		errors.Is(at(1500), jwt.ErrNotYetValid),
		at(2500),
		errors.Is(at(3500), jwt.ErrExpired),
	)

	// Output:
	// 1000 2000 3000
	// true <nil> true
}

func ExampleWithMaxAge() {
	signingKey := jwk.NewKey(exampleSecret)

	issuedAt := time.Unix(1000, 0)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithIssuedAt(&issuedAt),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	keySet := jwk.NewKeySet(signingKey)

	at := func(seconds int64, options ...func(*jwt.VerificationConfig)) error {
		return token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
			append(options, jwt.WithClock(func() time.Time { return time.Unix(seconds, 0) }))...,
		))
	}

	young := at(1200, jwt.WithMaxAge(time.Hour))
	old := at(5000, jwt.WithMaxAge(time.Hour))

	skewed := at(995, jwt.WithMaxAge(time.Hour))
	tolerated := at(995, jwt.WithMaxAge(time.Hour), jwt.WithLeeway(30*time.Second))

	fmt.Println(young, errors.Is(old, jwt.ErrTooOld))
	fmt.Println(errors.Is(skewed, jwt.ErrIssuedInFuture), tolerated)

	// Output:
	// <nil> true
	// true <nil>
}

func ExampleWithExpectedIssuer() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithType("at+jwt"),
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	keySet := jwk.NewKeySet(signingKey)

	accepted := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithExpectedIssuer("https://issuer.example"),
		jwt.WithExpectedSubject("alice"),
		jwt.WithExpectedType("at+jwt"),
	))

	otherIssuer := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithExpectedIssuer("https://other.example"),
		jwt.WithExpectedType("at+jwt"),
	))

	otherSubject := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithExpectedSubject("bob"),
		jwt.WithExpectedType("at+jwt"),
	))

	defaultType := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig())
	anyType := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(jwt.WithAnyType()))

	fmt.Println(accepted, errors.Is(otherIssuer, jwt.ErrUnexpectedIssuer))
	fmt.Println(errors.Is(otherSubject, jwt.ErrUnexpectedSubject))
	fmt.Println(errors.Is(defaultType, jwt.ErrUnexpectedType), anyType)

	// Output:
	// <nil> true
	// true
	// true <nil>
}

func ExampleWithAlgorithms() {
	signingKey := exampleECDSAKey(elliptic.P256())

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.ES256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	keySet := jwk.NewKeySet(signingKey.Public())

	accepted := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES256(), jwa.ES384()),
	))

	forbidden := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES384()),
	))

	limited := token.Verify(context.Background(), keySet, jwt.NewVerificationConfig(
		jwt.WithRequiredAlgorithms(jwa.ES384()),
		jwt.WithAlgorithms(jwa.ES256(), jwa.ES384()),
	))

	fmt.Println(accepted, errors.Is(forbidden, jwt.ErrForbiddenAlgorithm))
	fmt.Println(errors.Is(limited, jwt.ErrForbiddenAlgorithm))

	// Output:
	// <nil> true
	// true
}

func ExampleVerificationConfig() {
	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.ES256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
		jwt.WithExpectedSubject("alice"),
		jwt.WithExpectedAudience("https://api.example"),
		jwt.WithExpectedType("at+jwt"),
		jwt.WithLeeway(30*time.Second),
		jwt.WithMaxAge(time.Hour),
		jwt.WithClock(func() time.Time { return time.Unix(1000, 0) }),
	)

	fmt.Println(config.Algorithms(), config.ExpectedIssuer(), config.ExpectedSubject())
	fmt.Println(config.ExpectedAudience(), config.ExpectedType())
	fmt.Println(config.Leeway(), config.MaxAge(), config.Now().Unix())

	// Output:
	// [ES256] https://issuer.example alice
	// [https://api.example] at+jwt
	// 30s 1h0m0s 1000
}

func ExampleWithAllSignatures() {
	firstKey := exampleECDSAKey(elliptic.P256())
	secondKey := exampleECDSAKey(elliptic.P384())

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.ES256(), firstKey),
		jwt.WithSignature(jwa.ES384(), secondKey),
	)
	if err != nil {
		panic(err)
	}

	config := func(options ...func(*jwt.VerificationConfig)) jwt.VerificationConfig {
		return jwt.NewVerificationConfig(
			append(options, jwt.WithAlgorithms(jwa.ES256(), jwa.ES384()))...,
		)
	}

	oneKey := jwk.NewKeySet(firstKey.Public())

	one := token.Verify(context.Background(), oneKey, config())
	all := token.Verify(context.Background(), oneKey, config(jwt.WithAllSignatures()))

	both := token.Verify(context.Background(),
		jwk.NewKeySet(firstKey.Public(), secondKey.Public()), config(jwt.WithAllSignatures()),
	)

	fmt.Println(one, errors.Is(all, jwt.ErrUnverified), both)

	// Output:
	// <nil> true <nil>
}

func ExampleToken_VerifySignature() {
	firstKey := exampleECDSAKey(elliptic.P256())
	secondKey := exampleECDSAKey(elliptic.P384())

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.ES256(), firstKey),
		jwt.WithSignature(jwa.ES384(), secondKey),
	)
	if err != nil {
		panic(err)
	}

	document, err := json.Marshal(token)
	if err != nil {
		panic(err)
	}

	received := new(jwt.Token)
	if err := json.Unmarshal(document, received); err != nil {
		panic(err)
	}

	config := jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.ES256(), jwa.ES384()))

	second := received.Signatures()[1]

	named := received.VerifySignature(
		context.Background(), second, jwk.NewKeySet(secondKey.Public()), config,
	)

	other := received.VerifySignature(
		context.Background(), received.Signatures()[0], jwk.NewKeySet(secondKey.Public()), config,
	)

	fmt.Println(second.ProtectedHeader.Algorithm, named, other != nil)

	// Output:
	// ES384 <nil> true
}

func ExampleToken_Pending() {
	firstKey := exampleECDSAKey(elliptic.P256())
	secondKey := jwk.NewKey(exampleSecret, jwk.WithID("2026-09"))

	nameEachKey := func(token *jwt.Token) error {
		for i, signing := range token.Pending() {
			if signing.Algorithm == jwa.None() {
				return errors.New("profile: none is not a signature")
			}

			if err := token.AddProtectedHeader(i, header.WithKeyID(signing.Key.ID())); err != nil {
				return err
			}
		}

		return nil
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.ES256(), firstKey),
		jwt.WithSignature(jwa.HS256(), secondKey),
		jwt.WithIssuanceRule(nameEachKey),
	)
	if err != nil {
		panic(err)
	}

	if _, err := json.Marshal(token); err != nil {
		panic(err)
	}

	for _, signature := range token.Signatures() {
		fmt.Println(signature.ProtectedHeader.Algorithm, signature.ProtectedHeader.KeyID)
	}

	fmt.Println(errors.Is(token.AddProtectedHeader(2), jwt.ErrNoSuchSignature))

	// Output:
	// ES256 2026-08
	// HS256 2026-09
	// true
}

func ExampleToken_Claim() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithPrivateClaim("scope", "read write"),
		jwt.WithPrivateClaim("auth_time", 1000),
		jwt.WithPrivateClaim("cnf", map[string]any{"kid": "2026-08"}),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwt.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	scope, _, err := received.Claim[string]("scope")
	if err != nil {
		panic(err)
	}

	authTime, _, err := received.Claim[float64]("auth_time")
	if err != nil {
		panic(err)
	}

	confirmation, _, err := received.Claim[map[string]any]("cnf")
	if err != nil {
		panic(err)
	}

	_, _, wrongType := received.Claim[int]("auth_time")

	_, reserved := jwt.NewToken(jwt.WithPrivateClaim("sub", "alice"))

	fmt.Println(scope, authTime, confirmation["kid"])
	fmt.Println(errors.Is(wrongType, jwt.ErrMalformedClaim), errors.Is(reserved, jwt.ErrReservedClaim))

	// Output:
	// read write 1000 2026-08
	// true true
}

func ExampleWithSignature() {
	signingKey := exampleECDSAKey(elliptic.P256())

	keySetURL, err := url.Parse("https://issuer.example/.well-known/jwks.json")
	if err != nil {
		panic(err)
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(
			jwa.ES256(), signingKey,
			jws.WithProtectedHeader(header.WithKeyID(signingKey.ID())),
			jws.WithHeader(header.WithJWKSetURL(keySetURL)),
		),
	)
	if err != nil {
		panic(err)
	}

	if _, err := json.Marshal(token); err != nil {
		panic(err)
	}

	signature := token.Signatures()[0]

	fmt.Println(signature.ProtectedHeader.Algorithm, signature.ProtectedHeader.KeyID)
	fmt.Println(signature.Header.JWKSetURL)

	// Output:
	// ES256 2026-08
	// https://issuer.example/.well-known/jwks.json
}

func ExampleWithConfirmation() {
	signingKey := jwk.NewKey(exampleSecret)
	presenterKey := exampleECDSAKey(elliptic.P256())

	thumbprint, err := presenterKey.Public().ThumbprintID(crypto.SHA256)
	if err != nil {
		panic(err)
	}

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithConfirmation(jwt.Confirmation{
			JWK: presenterKey.Public(),

			Thumbprint: thumbprint,
		}),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	confirmation, err := token.Confirmation()
	if err != nil {
		panic(err)
	}

	_, present, err := token.Claim[map[string]any](jwt.ConfirmationClaim)
	if err != nil {
		panic(err)
	}

	keySetURL, err := url.Parse("https://presenter.example/.well-known/jwks.json")
	if err != nil {
		panic(err)
	}

	_, twoKeys := jwt.NewToken(jwt.WithConfirmation(jwt.Confirmation{
		JWK:   presenterKey.Public(),
		KeyID: "2026-08",

		KeySetURL: keySetURL,
	}))

	fmt.Println(confirmation.JWK.Type(), confirmation.Thumbprint == thumbprint, present)
	fmt.Println(jwt.ConfirmationClaim, jwt.ThumbprintConfirmation)
	fmt.Println(errors.Is(twoKeys, jwt.ErrMultipleConfirmationKeys))

	// Output:
	// EC true true
	// cnf jkt
	// true
}

func ExampleWithHeaderKey() {
	signingKey := exampleECDSAKey(elliptic.P256())

	policy := func(_ *jwk.Key, protected *header.Header) error {
		if protected.Type != "dpop+jwt" {
			return fmt.Errorf("profile: typ is %q", protected.Type)
		}

		return nil
	}

	proof, err := jwt.NewToken(
		jwt.WithType("dpop+jwt"),
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(
			jwa.ES256(), signingKey,
			jws.WithProtectedHeader(header.WithJWK(signingKey.Public())),
		),
	)
	if err != nil {
		panic(err)
	}

	other, err := jwt.NewToken(
		jwt.WithType("at+jwt"),
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(
			jwa.ES256(), signingKey,
			jws.WithProtectedHeader(header.WithJWK(signingKey.Public())),
		),
	)
	if err != nil {
		panic(err)
	}

	config := func(mediaType string) jwt.VerificationConfig {
		return jwt.NewVerificationConfig(
			jwt.WithAlgorithms(jwa.ES256()),
			jwt.WithExpectedType(mediaType),
			jwt.WithHeaderKey(policy),
		)
	}

	accepted := proof.Verify(context.Background(), nil, config("dpop+jwt"))
	refused := other.Verify(context.Background(), nil, config("at+jwt"))

	fmt.Println(accepted, errors.Is(refused, jwt.ErrHeaderKeyRefused))

	// Output:
	// <nil> true
}

func ExampleWithReplayCheck() {
	signingKey := jwk.NewKey(exampleSecret)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithID("Iq8SbJ3Ir1"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	store := new(exampleIDStore)

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.HS256()),
		jwt.WithReplayCheck(store),
	)

	keySet := jwk.NewKeySet(signingKey)

	first := token.Verify(context.Background(), keySet, config)
	second := token.Verify(context.Background(), keySet, config)

	anonymous, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)
	if err != nil {
		panic(err)
	}

	missing := anonymous.Verify(context.Background(), keySet, config)

	fmt.Println(first, errors.Is(second, jwt.ErrReplayedToken))
	fmt.Println(errors.Is(missing, jwt.ErrMissingRequiredClaim))

	// Output:
	// <nil> true
	// true
}

type exampleIDStore struct {
	mutex sync.Mutex
	seen  map[string]struct{}
}

func (store *exampleIDStore) Record(_ context.Context, id string, expiration *time.Time) (bool, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	if _, seen := store.seen[id]; seen {
		return false, nil
	}

	if store.seen == nil {
		store.seen = map[string]struct{}{}
	}

	_ = expiration

	store.seen[id] = struct{}{}

	return true, nil
}
