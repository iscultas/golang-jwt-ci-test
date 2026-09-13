package jwt_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

const (
	privateClaimKey   = "http://example.com/is_root"
	privateClaimValue = true
)

const symmetricKeyMaterial = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

const signedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjIxNDc0ODM2NDcsImlzcyI6ImpvZSIsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.H0e6hE4okWpIO7IAtLWZUuC1Q1awzQF2Mp_2dikBChU"

var expirationTime = time.Unix(2147483647, 0)

func key(t testing.TB, material string) *jwk.Key {
	t.Helper()

	decodedMaterial, err := base64.RawURLEncoding.DecodeString(material)
	if err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	return jwk.NewKey(decodedMaterial)
}

func newToken(t testing.TB, options ...func(*jwt.Token) error) *jwt.Token {
	t.Helper()

	token, err := jwt.NewToken(
		append(
			[]func(*jwt.Token) error{
				jwt.WithIssuer("joe"),
				jwt.WithExpirationTime(&expirationTime),
				jwt.WithPrivateClaim(privateClaimKey, privateClaimValue),
			},
			options...,
		)...,
	)
	if err != nil {
		t.Fatalf("cannot create token: %v", err)
	}

	return token
}

func unmarshalToken(t testing.TB, encodedToken string) *jwt.Token {
	t.Helper()

	token, err := jwt.Unmarshal(encodedToken)
	if err != nil {
		t.Fatalf("cannot decode token: %v", err)
	}

	return token
}

func assertClaimEqual(t *testing.T, claim string, claimTime, expectedClaimTime *time.Time) {
	t.Helper()

	switch {
	case claimTime == nil || expectedClaimTime == nil:
		if claimTime != expectedClaimTime {
			t.Errorf("got %s %v, want %v", claim, claimTime, expectedClaimTime)
		}
	case !claimTime.Equal(*expectedClaimTime):
		t.Errorf("got %s %v, want %v", claim, claimTime, expectedClaimTime)
	}
}

func assertClaimsEqual(t *testing.T, token, expectedToken *jwt.Token) {
	t.Helper()

	if token.Issuer() != expectedToken.Issuer() {
		t.Errorf("got issuer %s, want %s", token.Issuer(), expectedToken.Issuer())
	}

	assertClaimEqual(t, "expiration time", token.ExpirationTime(), expectedToken.ExpirationTime())
	assertClaimEqual(t, "not before", token.NotBefore(), expectedToken.NotBefore())
	assertClaimEqual(t, "issued at", token.IssuedAt(), expectedToken.IssuedAt())

	if token.PrivateClaim(privateClaimKey) != expectedToken.PrivateClaim(privateClaimKey) {
		t.Errorf(
			"got private claim %v, want %v",
			token.PrivateClaim(privateClaimKey),
			expectedToken.PrivateClaim(privateClaimKey),
		)
	}
}

func TestCompactSerialization(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		algorithm    jwa.Signer
		key          *jwk.Key
		encodedToken string
		decodedToken string
	}{
		{
			"WithoutSignature",
			jwa.None(),
			nil,
			"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJleHAiOjIxNDc0ODM2NDcsImlzcyI6ImpvZSIsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.",
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjIxNDc0ODM2NDcsImlzcyI6ImpvZSIsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.",
		},
		{
			"WithSignature",
			jwa.HS256(),
			key(t, symmetricKeyMaterial),
			signedToken,
			signedToken,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token := newToken(t, jwt.WithSignature(testCase.algorithm, testCase.key))

			t.Run("Encoding", func(t *testing.T) {
				if token.String() != testCase.encodedToken {
					t.Errorf("got %s, want %s", token.String(), testCase.encodedToken)
				}
			})

			t.Run("Decoding", func(t *testing.T) {
				assertClaimsEqual(t, unmarshalToken(t, testCase.decodedToken), token)
			})
		})
	}
}

func TestTemporalClaims(t *testing.T) {
	notBefore := time.Unix(1300819300, 0)
	issuedAt := time.Unix(1300819200, 0)

	token := newToken(
		t,
		jwt.WithNotBefore(&notBefore),
		jwt.WithIssuedAt(&issuedAt),
		jwt.WithSignature(jwa.HS256(), key(t, symmetricKeyMaterial)),
	)

	assertClaimsEqual(t, unmarshalToken(t, token.String()), token)
}

func TestUnmarshalingMalformedToken(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		token string
	}{
		{"Empty", ""},
		{"WithoutSignature", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UifQ"},
		{"WithTrailingPart", signedToken + ".eyJpc3MiOiJqb2UifQ"},
		{"NotBase64", "not.a.token"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := jwt.Unmarshal(testCase.token); err == nil {
				t.Error("got no error, want one")
			}
		})
	}
}

func TestVerifying(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	t.Run("Verified", func(t *testing.T) {
		token := unmarshalToken(t, signedToken)

		if err := token.Verify(t.Context(), jwk.NewKeySet(signingKey), jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("got error %v, want none", err)
		}
	})

	for _, testCase := range []struct {
		name   string
		token  func(*testing.T) *jwt.Token
		keySet *jwk.KeySet
	}{
		{
			"Expired",
			func(t *testing.T) *jwt.Token {
				t.Helper()

				expirationTime := time.Unix(0, 0)

				token, err := jwt.NewToken(
					jwt.WithExpirationTime(&expirationTime),
					jwt.WithSignature(jwa.HS256(), signingKey),
				)
				if err != nil {
					t.Fatalf("cannot create token: %v", err)
				}

				return token
			},
			jwk.NewKeySet(signingKey),
		},
		{
			"ForbiddenAlgorithm",
			func(t *testing.T) *jwt.Token {
				t.Helper()

				return newToken(t, jwt.WithSignature(jwa.None(), nil))
			},
			jwk.NewKeySet(signingKey),
		},
		{
			"UnknownKey",
			func(t *testing.T) *jwt.Token {
				t.Helper()

				return unmarshalToken(t, signedToken)
			},
			jwk.NewKeySet(jwk.NewKey([]byte("some other key"))),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.token(t).Verify(t.Context(), testCase.keySet, jwt.DefaultVerificationConfig); err == nil {
				t.Error("got no error, want one")
			}
		})
	}
}

func mintToken(t *testing.T, payloadJSON string) string {
	t.Helper()

	material, err := base64.RawURLEncoding.DecodeString(symmetricKeyMaterial)
	if err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	unsignedToken := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"HS256"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))

	signature, err := jwa.HS256().Sign([]byte(unsignedToken), material)
	if err != nil {
		t.Fatalf("cannot sign token: %v", err)
	}

	return unsignedToken + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifyingUnsignedToken(t *testing.T) {
	t.Run("Verifying", func(t *testing.T) {
		token := newToken(t)

		err := token.Verify(t.Context(), jwk.NewKeySet(key(t, symmetricKeyMaterial)), jwt.DefaultVerificationConfig)
		if !errors.Is(err, jwt.ErrUnsigned) {
			t.Errorf("got error %v, want %v", err, jwt.ErrUnsigned)
		}
	})

	t.Run("Encoding", func(t *testing.T) {
		if _, err := newToken(t).Marshal(); !errors.Is(err, jwt.ErrUnsigned) {
			t.Errorf("got error %v, want %v", err, jwt.ErrUnsigned)
		}
	})

	t.Run("Formatting", func(t *testing.T) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				t.Fatal("got no panic, want one")
			}

			err, isError := recovered.(error)
			if !isError || !errors.Is(err, jwt.ErrUnsigned) {
				t.Errorf("got panic %v, want %v", recovered, jwt.ErrUnsigned)
			}
		}()

		_ = newToken(t).String()
	})

	t.Run("JSONEncoding", func(t *testing.T) {
		if _, err := json.Marshal(newToken(t)); !errors.Is(err, jwt.ErrUnsigned) {
			t.Errorf("got error %v, want %v", err, jwt.ErrUnsigned)
		}
	})

	t.Run("Decoding", func(t *testing.T) {
		payload := strings.Split(signedToken, ".")[1]

		err := json.Unmarshal([]byte(`{"payload":"`+payload+`"}`), new(jwt.Token))
		if !errors.Is(err, jwt.ErrUnsigned) {
			t.Errorf("got error %v, want %v", err, jwt.ErrUnsigned)
		}
	})
}

func TestUnmarshalingMalformedClaims(t *testing.T) {
	for _, testCase := range []string{
		`{"iss":42}`,
		`{"sub":["joe"]}`,
		`{"aud":42}`,
		`{"aud":["joe",42]}`,
		`{"aud":null}`,
		`{"aud":{}}`,
		`{"exp":[]}`,
		`{"exp":"soon"}`,
		`{"nbf":null}`,
		`{"iat":{}}`,
		`{"jti":true}`,
	} {
		t.Run(testCase, func(t *testing.T) {
			_, err := jwt.Unmarshal(mintToken(t, testCase))

			if !errors.Is(err, jwt.ErrMalformedClaim) {
				t.Errorf("got error %v, want %v", err, jwt.ErrMalformedClaim)
			}
		})
	}
}

func TestVerifyingWithMismatchedKey(t *testing.T) {
	const rsaSignedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjIxNDc0ODM2NDcsImlzcyI6ImpvZSJ9.T3BlbiBTZXNhbWU"

	token := unmarshalToken(t, rsaSignedToken)

	err := token.Verify(t.Context(), jwk.NewKeySet(key(t, symmetricKeyMaterial)), jwt.DefaultVerificationConfig)
	if !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Errorf("got error %v, want %v", err, jwa.ErrInvalidKeyType)
	}
}

func TestVerifyingPreservesPayloadOctets(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		payload string
	}{
		{"UnsortedMembers", `{"iss":"joe","exp":2147483647}`},
		{"HtmlEscapableCharacters", `{"exp":2147483647,"iss":"joe & co <sales@example.com>"}`},
		{"InsignificantWhitespace", `{"exp": 2147483647, "iss": "joe"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token := unmarshalToken(t, mintToken(t, testCase.payload))

			if err := token.Verify(t.Context(),
				jwk.NewKeySet(key(t, symmetricKeyMaterial)), jwt.DefaultVerificationConfig,
			); err != nil {
				t.Errorf("got error %v, want none", err)
			}
		})
	}
}

func TestSigningFollowsClaimOptions(t *testing.T) {
	token, err := jwt.NewToken(
		jwt.WithSignature(jwa.HS256(), key(t, symmetricKeyMaterial)),
		jwt.WithIssuer("joe"),
		jwt.WithExpirationTime(&expirationTime),
		jwt.WithPrivateClaim(privateClaimKey, privateClaimValue),
	)
	if err != nil {
		t.Fatalf("cannot create token: %v", err)
	}

	encodedToken, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	if encodedToken != signedToken {
		t.Errorf("got %s, want %s", encodedToken, signedToken)
	}
}

func TestVerificationConfig(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	expiredAt := time.Now().Add(-30 * time.Second)
	notYetValidAt := time.Now().Add(time.Hour)

	issuedAnHourAgo := time.Now().Add(-time.Hour)
	issuedInAMinute := time.Now().Add(time.Minute)

	for _, testCase := range []struct {
		name          string
		options       []func(*jwt.Token) error
		config        jwt.VerificationConfig
		expectedError error
	}{
		{
			"ExpectedIssuer",
			nil,
			jwt.NewVerificationConfig(jwt.WithExpectedIssuer("joe")),
			nil,
		},
		{
			"UnexpectedIssuer",
			nil,
			jwt.NewVerificationConfig(jwt.WithExpectedIssuer("jane")),
			jwt.ErrUnexpectedIssuer,
		},
		{
			"ExpectedAudience",
			[]func(*jwt.Token) error{jwt.WithAudience("joe", "jane")},
			jwt.NewVerificationConfig(jwt.WithExpectedAudience("jane")),
			nil,
		},
		{
			"UnexpectedAudience",
			[]func(*jwt.Token) error{jwt.WithAudience("joe")},
			jwt.NewVerificationConfig(jwt.WithExpectedAudience("jane")),
			jwt.ErrUnexpectedAudience,
		},
		{
			"ExpiredWithinLeeway",
			[]func(*jwt.Token) error{jwt.WithExpirationTime(&expiredAt)},
			jwt.NewVerificationConfig(jwt.WithLeeway(time.Minute)),
			nil,
		},
		{
			"ExpiredBeyondLeeway",
			[]func(*jwt.Token) error{jwt.WithExpirationTime(&expiredAt)},
			jwt.NewVerificationConfig(jwt.WithLeeway(time.Second)),
			jwt.ErrExpired,
		},
		{
			"ForbiddenAlgorithm",
			nil,
			jwt.NewVerificationConfig(jwt.WithAlgorithms(jwa.RS256())),
			jwt.ErrForbiddenAlgorithm,
		},
		{
			"ExpectedAudienceAmongSeveralNames",
			[]func(*jwt.Token) error{jwt.WithAudience("joe")},
			jwt.NewVerificationConfig(jwt.WithExpectedAudience("jane", "joe")),
			nil,
		},
		{
			"UnexpectedAudienceAmongSeveralNames",
			[]func(*jwt.Token) error{jwt.WithAudience("joe")},
			jwt.NewVerificationConfig(jwt.WithExpectedAudience("jane", "jim")),
			jwt.ErrUnexpectedAudience,
		},
		{
			"SecondExpectedAudienceReplacesTheFirst",
			[]func(*jwt.Token) error{jwt.WithAudience("joe")},
			jwt.NewVerificationConfig(
				jwt.WithExpectedAudience("joe"),
				jwt.WithExpectedAudience("jane"),
			),
			jwt.ErrUnexpectedAudience,
		},
		{
			"ClockBeforeExpiration",
			[]func(*jwt.Token) error{jwt.WithExpirationTime(&expiredAt)},
			jwt.NewVerificationConfig(
				jwt.WithClock(func() time.Time { return expiredAt.Add(-time.Hour) }),
			),
			nil,
		},
		{
			"ClockAfterExpiration",
			nil,
			jwt.NewVerificationConfig(
				jwt.WithClock(func() time.Time { return expirationTime.Add(time.Second) }),
			),
			jwt.ErrExpired,
		},
		{
			"ClockBeforeNotBefore",
			[]func(*jwt.Token) error{jwt.WithNotBefore(&notYetValidAt)},
			jwt.NewVerificationConfig(
				jwt.WithClock(func() time.Time { return notYetValidAt.Add(-time.Hour) }),
			),
			jwt.ErrNotYetValid,
		},
		{
			"ClockAfterNotBefore",
			[]func(*jwt.Token) error{jwt.WithNotBefore(&notYetValidAt)},
			jwt.NewVerificationConfig(
				jwt.WithClock(func() time.Time { return notYetValidAt.Add(time.Second) }),
			),
			nil,
		},
		{
			"ExpectedSubject",
			[]func(*jwt.Token) error{jwt.WithSubject("alice")},
			jwt.NewVerificationConfig(jwt.WithExpectedSubject("alice")),
			nil,
		},
		{
			"UnexpectedSubject",
			[]func(*jwt.Token) error{jwt.WithSubject("alice")},
			jwt.NewVerificationConfig(jwt.WithExpectedSubject("bob")),
			jwt.ErrUnexpectedSubject,
		},
		{
			"ExpectedSubjectWithNoClaim",
			nil,
			jwt.NewVerificationConfig(jwt.WithExpectedSubject("alice")),
			jwt.ErrUnexpectedSubject,
		},
		{
			"MaxAgeWithinTheLimit",
			[]func(*jwt.Token) error{jwt.WithIssuedAt(&issuedAnHourAgo)},
			jwt.NewVerificationConfig(jwt.WithMaxAge(2 * time.Hour)),
			nil,
		},
		{
			"MaxAgeBeyondTheLimit",
			[]func(*jwt.Token) error{jwt.WithIssuedAt(&issuedAnHourAgo)},
			jwt.NewVerificationConfig(jwt.WithMaxAge(30 * time.Minute)),
			jwt.ErrTooOld,
		},
		{
			"MaxAgeBeyondTheLimitWithinLeeway",
			[]func(*jwt.Token) error{jwt.WithIssuedAt(&issuedAnHourAgo)},
			jwt.NewVerificationConfig(
				jwt.WithMaxAge(59*time.Minute), jwt.WithLeeway(2*time.Minute),
			),
			nil,
		},
		{
			"MaxAgeBeyondTheLimitAndBeyondLeeway",
			[]func(*jwt.Token) error{jwt.WithIssuedAt(&issuedAnHourAgo)},
			jwt.NewVerificationConfig(
				jwt.WithMaxAge(30*time.Minute), jwt.WithLeeway(2*time.Minute),
			),
			jwt.ErrTooOld,
		},
		{
			"IssuedInTheFuture",
			[]func(*jwt.Token) error{jwt.WithIssuedAt(&issuedInAMinute)},
			jwt.NewVerificationConfig(jwt.WithMaxAge(time.Hour)),
			jwt.ErrIssuedInFuture,
		},
		{
			"IssuedInTheFutureWithinLeeway",
			[]func(*jwt.Token) error{jwt.WithIssuedAt(&issuedInAMinute)},
			jwt.NewVerificationConfig(
				jwt.WithMaxAge(time.Hour), jwt.WithLeeway(2*time.Minute),
			),
			nil,
		},
		{
			"MaxAgeWithNoIssuedAt",
			nil,
			jwt.NewVerificationConfig(jwt.WithMaxAge(time.Hour)),
			jwt.ErrMissingRequiredClaim,
		},
		{
			"MaxAgeOfZeroAppliesNoCheck",
			nil,
			jwt.NewVerificationConfig(jwt.WithMaxAge(0)),
			nil,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token := newToken(
				t,
				append(testCase.options, jwt.WithSignature(jwa.HS256(), signingKey))...,
			)

			err := token.Verify(t.Context(), jwk.NewKeySet(signingKey), testCase.config)
			if !errors.Is(err, testCase.expectedError) {
				t.Errorf("got error %v, want %v", err, testCase.expectedError)
			}
		})
	}
}

const ed25519Seed = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"

func ed25519Key(t *testing.T, options ...func(*jwk.Key)) *jwk.Key {
	t.Helper()

	seed, err := base64.RawURLEncoding.DecodeString(ed25519Seed)
	if err != nil {
		t.Fatalf("cannot decode seed: %v", err)
	}

	return jwk.NewKey(ed25519.NewKeyFromSeed(seed), options...)
}

func TestEdDSASerialization(t *testing.T) {
	privateKey := ed25519Key(t)

	token := newToken(t, jwt.WithSignature(jwa.EdDSA(), privateKey))

	encodedToken, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	encodedHeader, err := base64.RawURLEncoding.DecodeString(strings.Split(encodedToken, ".")[0])
	if err != nil {
		t.Fatalf("cannot decode header: %v", err)
	}

	if !strings.Contains(string(encodedHeader), `"alg":"EdDSA"`) {
		t.Errorf(`got header %s, want it to name EdDSA`, encodedHeader)
	}

	encodedKey, err := json.Marshal(jwk.NewKey(privateKey.Material().(ed25519.PrivateKey).Public()))
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	publicKey := new(jwk.Key)
	if err := json.Unmarshal(encodedKey, publicKey); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	if err := unmarshalToken(t, encodedToken).Verify(t.Context(), jwk.NewKeySet(publicKey), jwt.DefaultVerificationConfig); err != nil {
		t.Errorf("cannot verify token: %v", err)
	}
}

const ecdsaKeyJSON = `{` +
	`"kty":"EC",` +
	`"crv":"P-256",` +
	`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
	`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
	`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"` +
	`}`

const ecdsaToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9." +
	"eyJleHAiOjIxNDc0ODM2NDcsImlzcyI6ImpvZSIsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
	"nZOQaU8X2_XoZIwxYWyozhN-D_JZwVbhruxxIhRN3Dszpec7xlH7vCYlPzRsLpT_aARgyefuwp-NcWPLCaA8QQ"

func ecdsaKey(t *testing.T) *jwk.Key {
	t.Helper()

	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(ecdsaKeyJSON), key); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	return key
}

func TestEcdsaSerialization(t *testing.T) {
	privateKey := ecdsaKey(t)

	encodedToken, err := newToken(t, jwt.WithSignature(jwa.ES256(), privateKey)).Marshal()
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	if encodedToken != ecdsaToken {
		t.Errorf("got %s, want %s", encodedToken, ecdsaToken)
	}

	err = unmarshalToken(t, ecdsaToken).Verify(t.Context(), jwk.NewKeySet(privateKey.Public()), jwt.DefaultVerificationConfig)
	if err != nil {
		t.Errorf("cannot verify token: %v", err)
	}
}

func TestMultipleSignatures(t *testing.T) {
	symmetric := key(t, symmetricKeyMaterial)
	jwk.WithAlgorithm(jwa.HS256())(symmetric)
	jwk.WithID("symmetric")(symmetric)

	signingKey := ed25519Key(t, jwk.WithAlgorithm(jwa.EdDSA()), jwk.WithID("ed25519"))

	verificationKey := jwk.NewKey(
		signingKey.Material().(ed25519.PrivateKey).Public(),
		jwk.WithAlgorithm(jwa.EdDSA()),
		jwk.WithID("ed25519"),
	)

	token := newToken(
		t,
		jwt.WithSignature(jwa.HS256(), symmetric),
		jwt.WithSignature(jwa.EdDSA(), signingKey),
	)

	encodedToken, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	t.Run("Encoding", func(t *testing.T) {
		var members struct {
			Signatures []jsontext.Value `json:"signatures"`
		}
		if err := json.Unmarshal(encodedToken, &members); err != nil {
			t.Fatalf("cannot decode token: %v", err)
		}

		if len(members.Signatures) != 2 {
			t.Errorf("got %d signatures in %s, want 2", len(members.Signatures), encodedToken)
		}
	})

	decode := func(t *testing.T) *jwt.Token {
		t.Helper()

		decodedToken := new(jwt.Token)
		if err := json.Unmarshal(encodedToken, decodedToken); err != nil {
			t.Fatalf("cannot decode token: %v", err)
		}

		return decodedToken
	}

	allSignatures := jwt.NewVerificationConfig(jwt.WithAllSignatures())

	t.Run("Verifying", func(t *testing.T) {
		if err := decode(t).Verify(t.Context(), jwk.NewKeySet(symmetric, verificationKey), allSignatures); err != nil {
			t.Errorf("cannot verify token: %v", err)
		}
	})

	t.Run("VerifyingWithOneKey", func(t *testing.T) {
		keySet := jwk.NewKeySet(verificationKey)

		if err := decode(t).Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); err != nil {
			t.Errorf("cannot verify token: %v", err)
		}

		if err := decode(t).Verify(t.Context(), keySet, allSignatures); !errors.Is(err, jwk.ErrNoSuitableKey) {
			t.Errorf("got error %v, want %v", err, jwk.ErrNoSuitableKey)
		}
	})

	t.Run("VerifyingWithNoKey", func(t *testing.T) {
		if err := decode(t).Verify(t.Context(), jwk.NewKeySet(), jwt.DefaultVerificationConfig); !errors.Is(err, jwt.ErrUnverified) {
			t.Errorf("got error %v, want %v", err, jwt.ErrUnverified)
		}
	})

	t.Run("Compact", func(t *testing.T) {
		if _, err := token.Marshal(); !errors.Is(err, jwt.ErrMultipleSignatures) {
			t.Errorf("got error %v, want %v", err, jwt.ErrMultipleSignatures)
		}
	})
}

func TestReservedPrivateClaim(t *testing.T) {
	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		t.Run(name, func(t *testing.T) {
			_, err := jwt.NewToken(jwt.WithPrivateClaim(name, "shadowed"))

			if !errors.Is(err, jwt.ErrReservedClaim) {
				t.Errorf("got error %v, want %v", err, jwt.ErrReservedClaim)
			}
		})
	}
}

func TestClaim(t *testing.T) {
	encoded, err := jwt.NewToken(
		jwt.WithPrivateClaim("note", "hello"),
		jwt.WithPrivateClaim("count", 3),
		jwt.WithSignature(jwa.HS256(), jwk.NewKey(make([]byte, 32))),
	)
	if err != nil {
		t.Fatalf("cannot build token: %v", err)
	}

	serialized, err := encoded.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize token: %v", err)
	}

	token, err := jwt.Unmarshal(serialized)
	if err != nil {
		t.Fatalf("cannot parse token: %v", err)
	}

	t.Run("Present", func(t *testing.T) {
		note, present, err := token.Claim[string]("note")
		if err != nil || !present || note != "hello" {
			t.Errorf("got (%q, %v, %v), want (%q, true, nil)", note, present, err, "hello")
		}
	})

	t.Run("Number", func(t *testing.T) {
		count, present, err := token.Claim[float64]("count")
		if err != nil || !present || count != 3 {
			t.Errorf("got (%v, %v, %v), want (3, true, nil)", count, present, err)
		}
	})

	t.Run("WrongType", func(t *testing.T) {
		_, present, err := token.Claim[int]("count")
		if !errors.Is(err, jwt.ErrMalformedClaim) {
			t.Errorf("got error %v, want %v", err, jwt.ErrMalformedClaim)
		}
		if !present {
			t.Error("got present false, want true: the claim is there, its type is not the one asked for")
		}
	})

	t.Run("Absent", func(t *testing.T) {
		value, present, err := token.Claim[string]("absent")
		if err != nil || present || value != "" {
			t.Errorf("got (%q, %v, %v), want (\"\", false, nil)", value, present, err)
		}
	})
}

func TestVerifyingPrecedesClaims(t *testing.T) {
	expiredAt := time.Unix(1300819380, 0)

	token := newToken(
		t,
		jwt.WithExpirationTime(&expiredAt),
		jwt.WithSignature(jwa.HS256(), key(t, symmetricKeyMaterial)),
	)

	encodedToken, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	otherKey := key(t, strings.Repeat("A", len(symmetricKeyMaterial)))

	err = unmarshalToken(t, encodedToken).Verify(t.Context(), jwk.NewKeySet(otherKey), jwt.DefaultVerificationConfig)

	if !errors.Is(err, jwt.ErrUnverified) {
		t.Errorf("got error %v, want %v", err, jwt.ErrUnverified)
	}

	if errors.Is(err, jwt.ErrExpired) {
		t.Error("got an expiry error before the signature was checked")
	}
}

func TestJsonSerialization(t *testing.T) {
	token := newToken(t, jwt.WithSignature(jwa.HS256(), key(t, symmetricKeyMaterial)))

	encodedToken, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	t.Run("Encoding", func(t *testing.T) {
		members := make(map[string]any)
		if err := json.Unmarshal(encodedToken, &members); err != nil {
			t.Fatalf("cannot decode token: %v", err)
		}

		for _, member := range []string{"protected", "payload", "signature"} {
			if _, ok := members[member]; !ok {
				t.Errorf("got no %s member in %s, want one", member, encodedToken)
			}
		}
	})

	t.Run("Decoding", func(t *testing.T) {
		decodedToken := new(jwt.Token)
		if err := json.Unmarshal(encodedToken, decodedToken); err != nil {
			t.Fatalf("cannot decode token: %v", err)
		}

		assertClaimsEqual(t, decodedToken, token)

		reencodedToken, err := json.Marshal(decodedToken)
		if err != nil {
			t.Fatalf("cannot encode token: %v", err)
		}

		if string(reencodedToken) != string(encodedToken) {
			t.Errorf("got %s, want %s", reencodedToken, encodedToken)
		}
	})
}

func TestFlattenedJsonSerializationWithUnprotectedHeader(t *testing.T) {
	token := newToken(
		t,
		jwt.WithSignature(
			jwa.HS256(), key(t, symmetricKeyMaterial), jws.WithHeader(header.WithKeyID("2010-12-29")),
		),
	)

	encodedToken, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("cannot encode token: %v", err)
	}

	t.Run("Encoding", func(t *testing.T) {
		var members struct {
			Payload         string         `json:"payload"`
			ProtectedHeader string         `json:"protected"`
			Header          jsontext.Value `json:"header"`
			Signature       string         `json:"signature"`
		}
		if err := json.Unmarshal(encodedToken, &members); err != nil {
			t.Fatalf("cannot decode token: %v", err)
		}

		if members.Payload == "" || members.ProtectedHeader == "" || members.Signature == "" {
			t.Errorf("got an incomplete flattened serialization %s", encodedToken)
		}

		if string(members.Header) != `{"kid":"2010-12-29"}` {
			t.Errorf("got header member %s, want %s", members.Header, `{"kid":"2010-12-29"}`)
		}
	})

	t.Run("Decoding", func(t *testing.T) {
		decodedToken := new(jwt.Token)
		if err := json.Unmarshal(encodedToken, decodedToken); err != nil {
			t.Fatalf("cannot decode token: %v", err)
		}

		reencodedToken, err := json.Marshal(decodedToken)
		if err != nil {
			t.Fatalf("cannot encode token: %v", err)
		}

		if string(reencodedToken) != string(encodedToken) {
			t.Errorf("got %s, want %s", reencodedToken, encodedToken)
		}
	})
}

func TestUnmarshalingNilSignature(t *testing.T) {
	payload := strings.Split(signedToken, ".")[1]

	err := json.Unmarshal([]byte(`{"payload":"`+payload+`","signatures":[null]}`), new(jwt.Token))
	if !errors.Is(err, jwt.ErrMalformedToken) {
		t.Errorf("got error %v, want %v", err, jwt.ErrMalformedToken)
	}
}

func TestMarshalKeepsTheSignedProtectedHeader(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	var protectedHeader *header.Header

	token := newToken(t, jwt.WithSignature(
		jwa.HS256(),
		signingKey,
		func(signature *jws.Signature) { protectedHeader = signature.ProtectedHeader },
	))

	signed, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	protectedHeader.KeyID = "added after the signature"

	again, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize again: %v", err)
	}

	if again != signed {
		t.Errorf("got %q, want %q", again, signed)
	}

	if err := unmarshalToken(t, again).Verify(t.Context(),
		jwk.NewKeySet(signingKey), jwt.DefaultVerificationConfig,
	); err != nil {
		t.Errorf("cannot verify: %v", err)
	}
}

func TestUnmarshalingTokenWithNoPayload(t *testing.T) {
	parts := strings.Split(signedToken, ".")
	protectedHeader, signature := parts[0], parts[2]

	for name, encodedToken := range map[string]string{
		"Empty":     `{}`,
		"Flattened": `{"protected":"` + protectedHeader + `","signature":"` + signature + `"}`,
		"General": `{"signatures":[{"protected":"` + protectedHeader +
			`","signature":"` + signature + `"}]}`,
		"EmptyPayload": `{"payload":"","protected":"` + protectedHeader +
			`","signature":"` + signature + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := json.Unmarshal([]byte(encodedToken), new(jwt.Token))
			if !errors.Is(err, jwt.ErrMalformedToken) {
				t.Errorf("got error %v, want %v", err, jwt.ErrMalformedToken)
			}
		})
	}
}

func TestVerifyingRefusesAnAlgorithmThatCannotVerify(t *testing.T) {
	payload := strings.Split(signedToken, ".")[1]
	signature := strings.Split(signedToken, ".")[2]

	for name, algorithm := range map[string]jwa.Algorithm{
		"KeyWrap":           jwa.A128KW(),
		"KeyWrapWithGCM":    jwa.A128GCMKW(),
		"ContentEncryption": jwa.A128GCM(),
	} {
		t.Run(name, func(t *testing.T) {
			protectedHeader := base64.RawURLEncoding.EncodeToString(
				[]byte(`{"alg":"` + algorithm.String() + `"}`),
			)

			token := unmarshalToken(t, protectedHeader+"."+payload+"."+signature)

			err := token.Verify(t.Context(),
				jwk.NewKeySet(key(t, symmetricKeyMaterial)),
				jwt.NewVerificationConfig(jwt.WithAlgorithms(algorithm)),
			)
			if !errors.Is(err, jwt.ErrForbiddenAlgorithm) {
				t.Errorf("got error %v, want %v", err, jwt.ErrForbiddenAlgorithm)
			}
		})
	}
}

func TestATokenWithoutPrivateClaimsWritesNoMap(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	for name, testCase := range map[string]struct {
		options []func(*jwt.Token) error
		want    string
	}{
		"registered claims only": {
			options: []func(*jwt.Token) error{jwt.WithIssuer("joe"), jwt.WithSubject("subject")},
			want:    `{"iss":"joe","sub":"subject"}`,
		},
		"no claims at all": {want: `{}`},
		"one private claim": {
			options: []func(*jwt.Token) error{jwt.WithIssuer("joe"), jwt.WithPrivateClaim("scope", "read")},
			want:    `{"iss":"joe","scope":"read"}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := append(
				slices.Clone(testCase.options),
				jwt.WithSignature(jwa.HS256(), signingKey),
			)

			token, err := jwt.NewToken(options...)
			if err != nil {
				t.Fatalf("cannot build the token: %v", err)
			}

			encoded, err := token.Marshal()
			if err != nil {
				t.Fatalf("cannot serialize: %v", err)
			}

			parts := strings.Split(encoded, ".")

			claims, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
			if err != nil {
				t.Fatalf("the payload does not decode: %v", err)
			}

			if string(claims) != testCase.want {
				t.Errorf("the claims set is %s, want %s", claims, testCase.want)
			}
		})
	}
}

func TestPrivateClaimOfATokenWithNoneGivesNil(t *testing.T) {
	token, err := jwt.NewToken(jwt.WithIssuer("joe"))
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	if claim := token.PrivateClaim("scope"); claim != nil {
		t.Errorf("PrivateClaim gave %#v, want nil", claim)
	}

	claim, present, err := token.Claim[string]("scope")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	if present {
		t.Errorf("Claim reports the claim is present, and it gave %q", claim)
	}
}

func TestClockIsReadOnceForBothTimeChecks(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	notBefore := time.Unix(1000, 0)
	expiration := time.Unix(2000, 0)

	reads := 0
	clock := func() time.Time {
		reads++

		return time.Unix(1500, 0)
	}

	token := newToken(
		t,
		jwt.WithNotBefore(&notBefore),
		jwt.WithExpirationTime(&expiration),
		jwt.WithSignature(jwa.HS256(), signingKey),
	)

	config := jwt.NewVerificationConfig(jwt.WithClock(clock))

	if err := token.Verify(t.Context(), jwk.NewKeySet(signingKey), config); err != nil {
		t.Fatalf("cannot verify token: %v", err)
	}

	if reads != 1 {
		t.Errorf("got %d reads of the clock, want 1", reads)
	}
}

func TestNowGivesTheClockOfTheConfiguration(t *testing.T) {
	fixed := time.Unix(1500, 0)

	config := jwt.NewVerificationConfig(jwt.WithClock(func() time.Time { return fixed }))
	if got := config.Now(); !got.Equal(fixed) {
		t.Errorf("got %v, want %v", got, fixed)
	}

	before := time.Now()

	now := jwt.NewVerificationConfig().Now()
	if now.Before(before) || now.After(time.Now()) {
		t.Errorf("got %v, want a time of this run", now)
	}
}

func TestVerifiedReportsWhatHappened(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)
	keySet := jwk.NewKeySet(signingKey)

	token := unmarshalToken(t, signedToken)
	if token.Verified() {
		t.Error("a token that Unmarshal gave reports itself verified")
	}

	other := jwk.NewKeySet(key(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err := token.Verify(t.Context(), other, jwt.DefaultVerificationConfig); err == nil {
		t.Fatal("a token verified under a key that did not sign it")
	}

	if token.Verified() {
		t.Error("a token reports itself verified after Verify gave an error")
	}

	if err := token.Verify(t.Context(), keySet, jwt.DefaultVerificationConfig); err != nil {
		t.Fatalf("cannot verify token: %v", err)
	}

	if !token.Verified() {
		t.Error("a token that verified does not report itself verified")
	}
}

func TestMalformedAudienceElementNamesItsKind(t *testing.T) {
	_, err := jwt.Unmarshal(mintToken(t, `{"aud":[[1]]}`))

	if !errors.Is(err, jwt.ErrMalformedClaim) {
		t.Fatalf("got error %v, want %v", err, jwt.ErrMalformedClaim)
	}

	const want = "jwt: malformed claim: got []interface {}"

	if got := err.Error(); !strings.Contains(got, want) {
		t.Errorf("got message %q, want it to hold %q", got, want)
	}
}
