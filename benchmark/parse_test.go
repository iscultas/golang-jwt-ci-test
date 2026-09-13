package benchmark_test

import (
	"testing"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/iscultas/jwt-go"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

func BenchmarkParse(b *testing.B) {
	serialized := signedTokens["HS256"]

	b.Run("lib=jwtgo", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			_, err := jwt.Unmarshal(serialized)
			fatal(b, err)
		}
	})

	b.Run("lib=golangjwt", func(b *testing.B) {
		parser := golangjwt.NewParser(golangjwt.WithoutClaimsValidation())

		b.ReportAllocs()

		for b.Loop() {
			_, _, err := parser.ParseUnverified(serialized, new(golangJwtClaims))
			fatal(b, err)
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		payload := []byte(serialized)

		b.ReportAllocs()

		for b.Loop() {
			_, err := jwxjwt.ParseInsecure(payload)
			fatal(b, err)
		}
	})
}
