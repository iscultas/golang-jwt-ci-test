package benchmark_test

import (
	"testing"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	jwxjwa "github.com/lestrrat-go/jwx/v3/jwa"
	jwxjwe "github.com/lestrrat-go/jwx/v3/jwe"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	jwtgoDirectKey = jwk.NewKey(
		contentKey,
		jwk.WithID(keyID),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.Encrypt, jwk.Decrypt),
	)
	jwtgoWrappingKey = jwk.NewKey(
		contentKey,
		jwk.WithID(keyID),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
	)
	jwtgoAgreementKey = jwk.NewKey(
		ecdsaPrivateKey,
		jwk.WithID(keyID),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.DeriveKey),
	)
	jwtgoRSAEncryptionKey = jwk.NewKey(
		rsaPrivateKey,
		jwk.WithID(keyID),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.WrapKey, jwk.UnwrapKey),
	)
)

type encryptionCase struct {
	name string

	jwtgoKeyManagement jwa.KeyEncrypter
	jwtgoEncryption    jwa.ContentEncrypter
	jwtgoRecipientKey  *jwk.Key
	jwtgoKey           *jwk.Key

	jwxKeyManagement jwxjwa.KeyEncryptionAlgorithm
	jwxEncryption    jwxjwa.ContentEncryptionAlgorithm
	jwxRecipientKey  any
	jwxKey           any
}

var encryptionCases = []encryptionCase{
	{
		name:               "dir",
		jwtgoKeyManagement: jwa.Dir(),
		jwtgoEncryption:    jwa.A256GCM(),
		jwtgoRecipientKey:  jwtgoDirectKey,
		jwtgoKey:           jwtgoDirectKey,
		jwxKeyManagement:   jwxjwa.DIRECT(),
		jwxEncryption:      jwxjwa.A256GCM(),
		jwxRecipientKey:    contentKey,
		jwxKey:             contentKey,
	},
	{
		name:               "A256KW",
		jwtgoKeyManagement: jwa.A256KW(),
		jwtgoEncryption:    jwa.A256GCM(),
		jwtgoRecipientKey:  jwtgoWrappingKey,
		jwtgoKey:           jwtgoWrappingKey,
		jwxKeyManagement:   jwxjwa.A256KW(),
		jwxEncryption:      jwxjwa.A256GCM(),
		jwxRecipientKey:    contentKey,
		jwxKey:             contentKey,
	},
	{
		name:               "ECDH-ES+A256KW",
		jwtgoKeyManagement: jwa.ECDHESA256KW(),
		jwtgoEncryption:    jwa.A256GCM(),
		jwtgoRecipientKey:  jwtgoAgreementKey.Public(),
		jwtgoKey:           jwtgoAgreementKey,
		jwxKeyManagement:   jwxjwa.ECDH_ES_A256KW(),
		jwxEncryption:      jwxjwa.A256GCM(),
		jwxRecipientKey:    &ecdsaPrivateKey.PublicKey,
		jwxKey:             ecdsaPrivateKey,
	},
	{
		name:               "RSA-OAEP-256",
		jwtgoKeyManagement: jwa.RSAOAEP256(),
		jwtgoEncryption:    jwa.A256GCM(),
		jwtgoRecipientKey:  jwtgoRSAEncryptionKey.Public(),
		jwtgoKey:           jwtgoRSAEncryptionKey,
		jwxKeyManagement:   jwxjwa.RSA_OAEP_256(),
		jwxEncryption:      jwxjwa.A256GCM(),
		jwxRecipientKey:    &rsaPrivateKey.PublicKey,
		jwxKey:             rsaPrivateKey,
	},
}

var encryptedTokens = func() map[string]string {
	tokens := make(map[string]string, len(encryptionCases))

	for _, testCase := range encryptionCases {
		token, err := newJwtgoEncryptedToken(
			testCase.jwtgoKeyManagement, testCase.jwtgoEncryption, testCase.jwtgoRecipientKey,
		)
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

func BenchmarkEncrypt(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		for _, testCase := range encryptionCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					token, err := newJwtgoEncryptedToken(
						testCase.jwtgoKeyManagement, testCase.jwtgoEncryption, testCase.jwtgoRecipientKey,
					)
					fatal(b, err)

					_, err = token.Marshal()
					fatal(b, err)
				}
			})
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		for _, testCase := range encryptionCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				serializer := jwxjwt.NewSerializer().Encrypt(
					jwxjwt.WithKey(testCase.jwxKeyManagement, testCase.jwxRecipientKey),
					jwxjwt.WithEncryptOption(jwxjwe.WithContentEncryption(testCase.jwxEncryption)),
				)

				b.ReportAllocs()

				for b.Loop() {
					token, err := newJwxToken()
					fatal(b, err)

					_, err = serializer.Serialize(token)
					fatal(b, err)
				}
			})
		}
	})
}

func BenchmarkDecrypt(b *testing.B) {
	b.Run("lib=jwtgo", func(b *testing.B) {
		for _, testCase := range encryptionCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				serialized := encryptedTokens[testCase.name]

				keySet := jwk.NewKeySet(testCase.jwtgoKey)

				config := jwt.NewDecryptionConfig(
					jwt.WithKeyManagementAlgorithms(testCase.jwtgoKeyManagement),
					jwt.WithContentEncryptionAlgorithms(testCase.jwtgoEncryption),
					jwt.WithVerification(
						jwt.WithExpectedIssuer(issuer),
						jwt.WithExpectedAudience(audience),
					),
				)

				b.ReportAllocs()

				for b.Loop() {
					token, err := jwt.Unmarshal(serialized)
					fatal(b, err)

					fatal(b, token.Decrypt(b.Context(), keySet, config))
				}
			})
		}
	})

	b.Run("lib=jwx", func(b *testing.B) {
		for _, testCase := range encryptionCases {
			b.Run("alg="+testCase.name, func(b *testing.B) {
				serialized := []byte(encryptedTokens[testCase.name])

				decryptOptions := []jwxjwe.DecryptOption{
					jwxjwe.WithKey(testCase.jwxKeyManagement, testCase.jwxKey),
				}

				parseOptions := []jwxjwt.ParseOption{
					jwxjwt.WithVerify(false),
					jwxjwt.WithValidate(true),
					jwxjwt.WithIssuer(issuer),
					jwxjwt.WithAudience(audience),
				}

				b.ReportAllocs()

				for b.Loop() {
					claims, err := jwxjwe.Decrypt(serialized, decryptOptions...)
					fatal(b, err)

					_, err = jwxjwt.Parse(claims, parseOptions...)
					fatal(b, err)
				}
			})
		}
	})
}
