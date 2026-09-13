package benchmark_test

import (
	"testing"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	jwxjwa "github.com/lestrrat-go/jwx/v3/jwa"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

type signatureCase struct {
	name string

	jwtgoAlgorithm       jwa.Signer
	jwtgoKey             *jwk.Key
	jwtgoVerificationKey *jwk.Key

	golangJwtMethod          golangjwt.SigningMethod
	golangJwtKey             any
	golangJwtVerificationKey any

	jwxAlgorithm       jwxjwa.SignatureAlgorithm
	jwxKey             jwxjwk.Key
	jwxVerificationKey jwxjwk.Key
}

var signatureCases = []signatureCase{
	{
		name:                     "HS256",
		jwtgoAlgorithm:           jwa.HS256(),
		jwtgoKey:                 jwtgoHMACKey,
		jwtgoVerificationKey:     jwtgoHMACKey,
		golangJwtMethod:          golangjwt.SigningMethodHS256,
		golangJwtKey:             hmacSecret,
		golangJwtVerificationKey: hmacSecret,
		jwxAlgorithm:             jwxjwa.HS256(),
		jwxKey:                   jwxHMACKey,
		jwxVerificationKey:       jwxHMACKey,
	},
	{
		name:                     "RS256",
		jwtgoAlgorithm:           jwa.RS256(),
		jwtgoKey:                 jwtgoRSAKey,
		jwtgoVerificationKey:     jwtgoRSAKey.Public(),
		golangJwtMethod:          golangjwt.SigningMethodRS256,
		golangJwtKey:             rsaPrivateKey,
		golangJwtVerificationKey: &rsaPrivateKey.PublicKey,
		jwxAlgorithm:             jwxjwa.RS256(),
		jwxKey:                   jwxRSAKey,
		jwxVerificationKey:       jwxRSAPublicKey,
	},
	{
		name:                     "PS256",
		jwtgoAlgorithm:           jwa.PS256(),
		jwtgoKey:                 jwtgoRSAKey,
		jwtgoVerificationKey:     jwtgoRSAKey.Public(),
		golangJwtMethod:          golangjwt.SigningMethodPS256,
		golangJwtKey:             rsaPrivateKey,
		golangJwtVerificationKey: &rsaPrivateKey.PublicKey,
		jwxAlgorithm:             jwxjwa.PS256(),
		jwxKey:                   jwxRSAKey,
		jwxVerificationKey:       jwxRSAPublicKey,
	},
	{
		name:                     "ES256",
		jwtgoAlgorithm:           jwa.ES256(),
		jwtgoKey:                 jwtgoECDSAKey,
		jwtgoVerificationKey:     jwtgoECDSAKey.Public(),
		golangJwtMethod:          golangjwt.SigningMethodES256,
		golangJwtKey:             ecdsaPrivateKey,
		golangJwtVerificationKey: &ecdsaPrivateKey.PublicKey,
		jwxAlgorithm:             jwxjwa.ES256(),
		jwxKey:                   jwxECDSAKey,
		jwxVerificationKey:       jwxECDSAPublicKey,
	},
	{
		name:                     "EdDSA",
		jwtgoAlgorithm:           jwa.EdDSA(),
		jwtgoKey:                 jwtgoEd25519Key,
		jwtgoVerificationKey:     jwtgoEd25519Key.Public(),
		golangJwtMethod:          golangjwt.SigningMethodEdDSA,
		golangJwtKey:             ed25519PrivateKey,
		golangJwtVerificationKey: ed25519PrivateKey.Public(),
		jwxAlgorithm:             jwxjwa.EdDSA(),
		jwxKey:                   jwxEd25519Key,
		jwxVerificationKey:       jwxEd25519PublicKey,
	},
}

func BenchmarkSign(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		for _, testCase := range signatureCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					token, err := newJwtgoToken(testCase.jwtgoAlgorithm, testCase.jwtgoKey)
					fatal(b, err)

					_, err = token.Marshal()
					fatal(b, err)
				}
			})
		}
	})

	b.Run("lib=golangjwt", func(b *testing.B) {
		for _, testCase := range signatureCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					_, err := newGolangJwtToken(testCase.golangJwtMethod).
						SignedString(testCase.golangJwtKey)
					fatal(b, err)
				}
			})
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		for _, testCase := range signatureCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					token, err := newJwxToken()
					fatal(b, err)

					_, err = jwxjwt.Sign(token, jwxjwt.WithKey(testCase.jwxAlgorithm, testCase.jwxKey))
					fatal(b, err)
				}
			})
		}
	})
}
