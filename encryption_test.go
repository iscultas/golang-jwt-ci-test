package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func contentEncryptionKey(t *testing.T, encryption jwa.ContentEncrypter) *jwk.Key {
	t.Helper()

	return jwk.NewKey(
		make([]byte, encryption.KeySize()),
		jwk.WithPublicKeyUse(jwk.Encryption),
		jwk.WithOperations(jwk.Encrypt, jwk.Decrypt),
	)
}

func TestDecryptChecksClaims(t *testing.T) {
	encryptionKey := contentEncryptionKey(t, jwa.A256GCM())

	expired := time.Now().Add(-time.Hour)

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithExpirationTime(&expired),
		jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), encryptionKey),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	decoded, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	if err := decoded.Decrypt(t.Context(),
		jwk.NewKeySet(encryptionKey), jwt.DefaultDecryptionConfig,
	); !errors.Is(err, jwt.ErrExpired) {
		t.Errorf("got %v, want ErrExpired", err)
	}
}

func TestDecryptRefusesAForbiddenAlgorithm(t *testing.T) {
	encryptionKey := contentEncryptionKey(t, jwa.A256GCM())

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), encryptionKey),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	for _, config := range []jwt.DecryptionConfig{
		jwt.NewDecryptionConfig(jwt.WithKeyManagementAlgorithms(jwa.A128KW(), jwa.RSAOAEP256())),
		jwt.NewDecryptionConfig(jwt.WithContentEncryptionAlgorithms(jwa.A128CBCHS256())),
	} {
		decoded, err := jwt.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("cannot parse: %v", err)
		}

		if err := decoded.Decrypt(t.Context(),
			jwk.NewKeySet(encryptionKey), config,
		); !errors.Is(err, jwt.ErrForbiddenKeyManagement) {
			t.Errorf("got %v, want ErrForbiddenKeyManagement", err)
		}
	}
}

func TestDecryptRejectsAnUnencryptedToken(t *testing.T) {
	decoded, err := jwt.Unmarshal(signedToken)
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	if err := decoded.Decrypt(t.Context(),
		jwk.NewKeySet(key(t, symmetricKeyMaterial)), jwt.DefaultDecryptionConfig,
	); !errors.Is(err, jwt.ErrUnencrypted) {
		t.Errorf("got %v, want ErrUnencrypted", err)
	}
}

func TestDecryptFillsThePayloadThatUnmarshalMade(t *testing.T) {
	key := contentEncryptionKey(t, jwa.A256GCM())

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithPrivateClaim("scope", "read"),
		jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), key),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	decoded, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	if issuer := decoded.Issuer(); issuer != "" {
		t.Errorf("the issuer before decryption is %q, want the empty string", issuer)
	}

	if scope := decoded.PrivateClaim("scope"); scope != nil {
		t.Errorf("the private claim before decryption is %#v, want nil", scope)
	}

	if err := decoded.Decrypt(t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig); err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if issuer := decoded.Issuer(); issuer != "joe" {
		t.Errorf("the issuer after decryption is %q, want %q", issuer, "joe")
	}

	if scope := decoded.PrivateClaim("scope"); scope != "read" {
		t.Errorf("the private claim after decryption is %#v, want %q", scope, "read")
	}
}

func TestDecryptReplacesEveryClaimOfATokenItEncrypted(t *testing.T) {
	key := contentEncryptionKey(t, jwa.A256GCM())

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithSubject("subject"),
		jwt.WithPrivateClaim("scope", "read"),
		jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), key),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	if err := token.Decrypt(t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig); err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if issuer := token.Issuer(); issuer != "joe" {
		t.Errorf("got issuer %q, want %q", issuer, "joe")
	}

	if subject := token.Subject(); subject != "subject" {
		t.Errorf("got subject %q, want %q", subject, "subject")
	}

	if scope := token.PrivateClaim("scope"); scope != "read" {
		t.Errorf("got private claim %#v, want %q", scope, "read")
	}
}

func TestDecryptRecordsThatTheClaimsAreAuthentic(t *testing.T) {
	key := contentEncryptionKey(t, jwa.A256GCM())

	token, err := jwt.NewToken(
		jwt.WithIssuer("joe"),
		jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), key),
	)
	if err != nil {
		t.Fatalf("cannot build the token: %v", err)
	}

	encoded, err := token.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	decoded, err := jwt.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	if decoded.Verified() {
		t.Error("a JWE that Unmarshal gave reports itself verified")
	}

	if err := decoded.Decrypt(t.Context(), jwk.NewKeySet(key), jwt.DefaultDecryptionConfig); err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if !decoded.Verified() {
		t.Error("a JWE that decrypted does not report itself verified")
	}
}

func TestDecryptChecksTheType(t *testing.T) {
	withOuterType := func(mediaType string) func(*header.Header) {
		return func(protectedHeader *header.Header) { protectedHeader.Type = mediaType }
	}

	for _, testCase := range []struct {
		name          string
		outerType     string
		innerType     string
		nested        bool
		config        jwt.DecryptionConfig
		expectedError error
	}{
		{
			"DirectDefaultAcceptsJWT",
			"JWT", "", false,
			jwt.DefaultDecryptionConfig,
			nil,
		},
		{
			"DirectDefaultRejectsAProfileType",
			"at+jwt", "", false,
			jwt.DefaultDecryptionConfig,
			jwt.ErrUnexpectedType,
		},
		{
			"DirectExpectedTypeMatchesTheJweHeader",
			"at+jwt", "", false,
			jwt.NewDecryptionConfig(jwt.WithVerification(jwt.WithExpectedType("at+jwt"))),
			nil,
		},
		{
			"NestedReadsTheInnerHeader",
			"JWT", "at+jwt", true,
			jwt.NewDecryptionConfig(jwt.WithVerification(jwt.WithExpectedType("at+jwt"))),
			nil,
		},
		{
			"NestedOuterHeaderCannotSupplyTheType",
			"at+jwt", "JWT", true,
			jwt.NewDecryptionConfig(jwt.WithVerification(jwt.WithExpectedType("at+jwt"))),
			jwt.ErrUnexpectedType,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			encryptionKey := contentEncryptionKey(t, jwa.A256GCM())

			options := []func(*jwt.Token) error{
				jwt.WithIssuer("joe"),
				jwt.WithType(testCase.innerType),
				jwt.WithEncryption(
					jwa.Dir(), jwa.A256GCM(), encryptionKey, withOuterType(testCase.outerType),
				),
			}

			keySet := jwk.NewKeySet(encryptionKey)

			if testCase.nested {
				signingKey := key(t, symmetricKeyMaterial)
				options = append(options, jwt.WithSignature(jwa.HS256(), signingKey))
				keySet = jwk.NewKeySet(encryptionKey, signingKey)
			}

			token, err := jwt.NewToken(options...)
			if err != nil {
				t.Fatalf("cannot build the token: %v", err)
			}

			encoded, err := token.Marshal()
			if err != nil {
				t.Fatalf("cannot serialize: %v", err)
			}

			err = unmarshalToken(t, encoded).Decrypt(t.Context(), keySet, testCase.config)
			if !errors.Is(err, testCase.expectedError) {
				t.Errorf("got error %v, want %v", err, testCase.expectedError)
			}
		})
	}
}
