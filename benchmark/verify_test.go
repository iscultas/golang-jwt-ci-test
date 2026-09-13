package benchmark_test

import (
	"testing"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

var signedTokens = func() map[string]string {
	tokens := make(map[string]string, len(signatureCases))

	for _, testCase := range signatureCases {
		token, err := newJwtgoToken(testCase.jwtgoAlgorithm, testCase.jwtgoKey)
		if err != nil {
			panic(err)
		}

		serialized, err := token.Marshal()
		if err != nil {
			panic(err)
		}

		tokens[testCase.name] = serialized
	}

	return tokens
}()

func BenchmarkVerify(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		for _, testCase := range signatureCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				serialized := signedTokens[testCase.name]

				keySet := jwk.NewKeySet(testCase.jwtgoVerificationKey)

				config := jwt.NewVerificationConfig(
					jwt.WithAlgorithms(testCase.jwtgoAlgorithm),
					jwt.WithExpectedIssuer(issuer),
					jwt.WithExpectedAudience(audience),
				)

				b.ReportAllocs()

				for b.Loop() {
					token, err := jwt.Unmarshal(serialized)
					fatal(b, err)

					fatal(b, token.Verify(b.Context(), keySet, config))
				}
			})
		}
	})

	b.Run("lib=golangjwt", func(b *testing.B) {
		for _, testCase := range signatureCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				serialized := signedTokens[testCase.name]

				key := testCase.golangJwtVerificationKey
				keyFunc := func(*golangjwt.Token) (any, error) { return key, nil }

				parser := golangjwt.NewParser(
					golangjwt.WithValidMethods([]string{testCase.name}),
					golangjwt.WithIssuer(issuer),
					golangjwt.WithAudience(audience),
					golangjwt.WithExpirationRequired(),
				)

				b.ReportAllocs()

				for b.Loop() {
					_, err := parser.ParseWithClaims(serialized, new(golangJwtClaims), keyFunc)
					fatal(b, err)
				}
			})
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		for _, testCase := range signatureCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				serialized := []byte(signedTokens[testCase.name])

				options := []jwxjwt.ParseOption{
					jwxjwt.WithKey(testCase.jwxAlgorithm, testCase.jwxVerificationKey),
					jwxjwt.WithValidate(true),
					jwxjwt.WithIssuer(issuer),
					jwxjwt.WithAudience(audience),
				}

				b.ReportAllocs()

				for b.Loop() {
					_, err := jwxjwt.Parse(serialized, options...)
					fatal(b, err)
				}
			})
		}
	})
}
