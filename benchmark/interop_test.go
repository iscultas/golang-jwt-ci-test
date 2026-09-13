package benchmark_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwk"
	jwxjwe "github.com/lestrrat-go/jwx/v3/jwe"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	jwtgoLib     = "jwtgo"
	golangJwtLib = "golangjwt"
	jwxLib       = "jwx"
)

var libraries = []string{jwtgoLib, golangJwtLib, jwxLib}

func sign(library string, testCase signatureCase) (string, error) {
	switch library {
	case jwtgoLib:
		token, err := newJwtgoToken(testCase.jwtgoAlgorithm, testCase.jwtgoKey)
		if err != nil {
			return "", err
		}

		return token.Marshal()

	case golangJwtLib:
		return newGolangJwtToken(testCase.golangJwtMethod).SignedString(testCase.golangJwtKey)

	default:
		token, err := newJwxToken()
		if err != nil {
			return "", err
		}

		serialized, err := jwxjwt.Sign(token, jwxjwt.WithKey(testCase.jwxAlgorithm, testCase.jwxKey))

		return string(serialized), err
	}
}

func verify(library string, testCase signatureCase, serialized string) error {
	switch library {
	case jwtgoLib:
		token, err := jwt.Unmarshal(serialized)
		if err != nil {
			return err
		}

		return token.Verify(context.Background(), jwk.NewKeySet(testCase.jwtgoVerificationKey), jwt.NewVerificationConfig(
			jwt.WithAlgorithms(testCase.jwtgoAlgorithm),
			jwt.WithExpectedIssuer(issuer),
			jwt.WithExpectedAudience(audience),
		))

	case golangJwtLib:
		_, err := golangjwt.NewParser(
			golangjwt.WithValidMethods([]string{testCase.name}),
			golangjwt.WithIssuer(issuer),
			golangjwt.WithAudience(audience),
			golangjwt.WithExpirationRequired(),
		).ParseWithClaims(serialized, new(golangJwtClaims), func(*golangjwt.Token) (any, error) {
			return testCase.golangJwtVerificationKey, nil
		})

		return err

	default:
		_, err := jwxjwt.Parse(
			[]byte(serialized),
			jwxjwt.WithKey(testCase.jwxAlgorithm, testCase.jwxVerificationKey),
			jwxjwt.WithValidate(true),
			jwxjwt.WithIssuer(issuer),
			jwxjwt.WithAudience(audience),
		)

		return err
	}
}

func TestSignatureArmsAgree(t *testing.T) {
	for _, testCase := range signatureCases {
		t.Run(testCase.name, func(t *testing.T) {
			for _, producer := range libraries {
				serialized, err := sign(producer, testCase)
				if err != nil {
					t.Fatalf("%s cannot sign: %v", producer, err)
				}

				for _, consumer := range libraries {
					if err := verify(consumer, testCase, serialized); err != nil {
						t.Errorf("%s cannot verify a token of %s: %v", consumer, producer, err)
					}
				}
			}
		})
	}
}

func TestEncryptionArmsAgree(t *testing.T) {
	for _, testCase := range encryptionCases {
		t.Run(testCase.name, func(t *testing.T) {
			jwtgoToken, err := newJwtgoEncryptedToken(
				testCase.jwtgoKeyManagement, testCase.jwtgoEncryption, testCase.jwtgoRecipientKey,
			)
			if err != nil {
				t.Fatalf("jwtgo cannot make a token: %v", err)
			}

			fromJwtgo, err := jwtgoToken.Marshal()
			if err != nil {
				t.Fatalf("jwtgo cannot encrypt: %v", err)
			}

			jwxToken, err := newJwxToken()
			if err != nil {
				t.Fatalf("jwx cannot make a token: %v", err)
			}

			encrypted, err := jwxjwt.NewSerializer().Encrypt(
				jwxjwt.WithKey(testCase.jwxKeyManagement, testCase.jwxRecipientKey),
				jwxjwt.WithEncryptOption(jwxjwe.WithContentEncryption(testCase.jwxEncryption)),
			).Serialize(jwxToken)
			if err != nil {
				t.Fatalf("jwx cannot encrypt: %v", err)
			}

			for producer, serialized := range map[string]string{
				jwtgoLib: fromJwtgo,
				jwxLib:   string(encrypted),
			} {
				token, err := jwt.Unmarshal(serialized)
				if err != nil {
					t.Errorf("jwtgo cannot read a token of %s: %v", producer, err)
					continue
				}

				err = token.Decrypt(t.Context(), jwk.NewKeySet(testCase.jwtgoKey), jwt.NewDecryptionConfig(
					jwt.WithKeyManagementAlgorithms(testCase.jwtgoKeyManagement),
					jwt.WithContentEncryptionAlgorithms(testCase.jwtgoEncryption),
					jwt.WithVerification(
						jwt.WithExpectedIssuer(issuer),
						jwt.WithExpectedAudience(audience),
					),
				))
				if err != nil {
					t.Errorf("jwtgo cannot decrypt a token of %s: %v", producer, err)
				}

				claims, err := jwxjwe.Decrypt(
					[]byte(serialized), jwxjwe.WithKey(testCase.jwxKeyManagement, testCase.jwxKey),
				)
				if err != nil {
					t.Errorf("jwx cannot decrypt a token of %s: %v", producer, err)
					continue
				}

				_, err = jwxjwt.Parse(
					claims,
					jwxjwt.WithVerify(false),
					jwxjwt.WithValidate(true),
					jwxjwt.WithIssuer(issuer),
					jwxjwt.WithAudience(audience),
				)
				if err != nil {
					t.Errorf("jwx cannot read the claims of a token of %s: %v", producer, err)
				}
			}
		})
	}
}

func TestTokenSignsOnce(t *testing.T) {
	token, err := newJwtgoToken(signatureCases[0].jwtgoAlgorithm, signatureCases[0].jwtgoKey)
	if err != nil {
		t.Fatalf("cannot make token: %v", err)
	}

	if len(token.Pending()) != 1 {
		t.Fatalf("got %d pending signatures before marshalling, want 1", len(token.Pending()))
	}

	if _, err := token.Marshal(); err != nil {
		t.Fatalf("cannot marshal token: %v", err)
	}

	if pending := token.Pending(); len(pending) != 0 {
		t.Errorf("got %d pending signatures after marshalling, want 0", len(pending))
	}

	if signatures := token.Signatures(); len(signatures) != 1 {
		t.Errorf("got %d signatures after marshalling, want 1", len(signatures))
	}
}

func TestHeadersAreComparable(t *testing.T) {
	for _, testCase := range signatureCases {
		t.Run(testCase.name, func(t *testing.T) {
			for _, producer := range libraries {
				serialized, err := sign(producer, testCase)
				if err != nil {
					t.Fatalf("%s cannot sign: %v", producer, err)
				}

				encoded, _, found := strings.Cut(serialized, ".")
				if !found {
					t.Fatalf("%s gave no compact serialization", producer)
				}

				decoded, err := base64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatalf("cannot decode the header of %s: %v", producer, err)
				}

				header := make(map[string]any)
				if err := json.Unmarshal(decoded, &header); err != nil {
					t.Fatalf("cannot read the header of %s: %v", producer, err)
				}

				for _, parameter := range []string{"alg", "typ", "kid"} {
					if _, present := header[parameter]; !present {
						t.Errorf("%s wrote no %q: %s", producer, parameter, decoded)
					}
				}
			}
		})
	}
}
