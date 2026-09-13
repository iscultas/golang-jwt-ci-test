package benchmark_test

import (
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	issuer     = "https://issuer.example"
	subject    = "alice"
	audience   = "https://api.example"
	tokenID    = "7ce2b1a4"
	scopeClaim = "scope"
	scopeValue = "read write"
)

var (
	issuedAt   = time.Now().Truncate(time.Second)
	notBefore  = issuedAt
	expiration = issuedAt.Add(time.Hour)
)

type golangJwtClaims struct {
	golangjwt.RegisteredClaims

	Scope string `json:"scope,omitempty"`
}

func newJwtgoToken(algorithm jwa.Signer, key *jwk.Key) (*jwt.Token, error) {
	return jwt.NewToken(
		jwt.WithIssuer(issuer),
		jwt.WithSubject(subject),
		jwt.WithAudience(audience),
		jwt.WithExpirationTime(&expiration),
		jwt.WithNotBefore(&notBefore),
		jwt.WithIssuedAt(&issuedAt),
		jwt.WithID(tokenID),
		jwt.WithPrivateClaim(scopeClaim, scopeValue),
		jwt.WithSignature(algorithm, key, jws.WithProtectedHeader(header.WithKeyID(key.ID()))),
	)
}

func newJwtgoEncryptedToken(
	algorithm jwa.KeyEncrypter, encryption jwa.ContentEncrypter, key *jwk.Key,
) (*jwt.Token, error) {
	return jwt.NewToken(
		jwt.WithIssuer(issuer),
		jwt.WithSubject(subject),
		jwt.WithAudience(audience),
		jwt.WithExpirationTime(&expiration),
		jwt.WithNotBefore(&notBefore),
		jwt.WithIssuedAt(&issuedAt),
		jwt.WithID(tokenID),
		jwt.WithPrivateClaim(scopeClaim, scopeValue),
		jwt.WithEncryption(algorithm, encryption, key),
	)
}

func newGolangJwtToken(method golangjwt.SigningMethod) *golangjwt.Token {
	token := golangjwt.NewWithClaims(method, &golangJwtClaims{
		Scope:     scopeValue,
		Issuer:    issuer,
		Subject:   subject,
		Audience:  golangjwt.ClaimStrings{audience},
		ExpiresAt: golangjwt.NewNumericDate(expiration),
		NotBefore: golangjwt.NewNumericDate(notBefore),
		IssuedAt:  golangjwt.NewNumericDate(issuedAt),
		ID:        tokenID,
	})

	token.Header["kid"] = keyID

	return token
}

func newJwxToken() (jwxjwt.Token, error) {
	return jwxjwt.NewBuilder().
		Issuer(issuer).
		Subject(subject).
		Audience([]string{audience}).
		Expiration(expiration).
		NotBefore(notBefore).
		IssuedAt(issuedAt).
		JwtID(tokenID).
		Claim(scopeClaim, scopeValue).
		Build()
}
