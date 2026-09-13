package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func signWithHeader(t testing.TB, signingKey *jwk.Key, protectedHeader *header.Header) (string, string) {
	t.Helper()

	encodedHeader, err := protectedHeader.Marshal()
	if err != nil {
		t.Fatalf("cannot encode the header: %v", err)
	}

	payload := strings.Split(signedToken, ".")[1]

	signature, err := jwa.HS256().Sign([]byte(encodedHeader+"."+payload), signingKey.Material())
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	return encodedHeader, base64.RawURLEncoding.EncodeToString(signature)
}

func compactWithHeader(t testing.TB, signingKey *jwk.Key, protectedHeader *header.Header) string {
	t.Helper()

	encodedHeader, signature := signWithHeader(t, signingKey, protectedHeader)

	return encodedHeader + "." + strings.Split(signedToken, ".")[1] + "." + signature
}

func TestDefaultTypeCheck(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	for _, testCase := range []struct {
		name          string
		mediaType     string
		expectedError error
	}{
		{"NoType", "", nil},
		{"JWT", "JWT", nil},
		{"LowercaseJWT", "jwt", nil},
		{"QualifiedJWT", "application/JWT", nil},
		{"QualifiedLowercaseJWT", "application/jwt", nil},
		{"ProfileType", "at+jwt", jwt.ErrUnexpectedType},
		{"QualifiedProfileType", "application/at+jwt", jwt.ErrUnexpectedType},
		{"UnrelatedType", "text/plain", jwt.ErrUnexpectedType},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token := unmarshalToken(t, compactWithHeader(
				t, signingKey, &header.Header{Type: testCase.mediaType, Algorithm: jwa.HS256()},
			))

			err := token.Verify(t.Context(), jwk.NewKeySet(signingKey), jwt.DefaultVerificationConfig)
			if !errors.Is(err, testCase.expectedError) {
				t.Errorf("got error %v, want %v", err, testCase.expectedError)
			}
		})
	}
}

func TestExpectedTypeCheck(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	for _, testCase := range []struct {
		name          string
		mediaType     string
		config        jwt.VerificationConfig
		expectedError error
	}{
		{
			"Match",
			"at+jwt",
			jwt.NewVerificationConfig(jwt.WithExpectedType("at+jwt")),
			nil,
		},
		{
			"MatchIgnoresCase",
			"AT+JWT",
			jwt.NewVerificationConfig(jwt.WithExpectedType("at+jwt")),
			nil,
		},
		{
			"MatchSuppliesTheApplicationPrefix",
			"application/at+jwt",
			jwt.NewVerificationConfig(jwt.WithExpectedType("at+jwt")),
			nil,
		},
		{
			"ExpectationSuppliesTheApplicationPrefix",
			"at+jwt",
			jwt.NewVerificationConfig(jwt.WithExpectedType("application/at+jwt")),
			nil,
		},
		{
			"Mismatch",
			"dpop+jwt",
			jwt.NewVerificationConfig(jwt.WithExpectedType("at+jwt")),
			jwt.ErrUnexpectedType,
		},
		{
			"PlainJWTIsNotTheProfile",
			"JWT",
			jwt.NewVerificationConfig(jwt.WithExpectedType("at+jwt")),
			jwt.ErrUnexpectedType,
		},
		{
			"NoTypeIsNotTheProfile",
			"",
			jwt.NewVerificationConfig(jwt.WithExpectedType("at+jwt")),
			jwt.ErrUnexpectedType,
		},
		{
			"AnyTypeAcceptsAProfileType",
			"at+jwt",
			jwt.NewVerificationConfig(jwt.WithAnyType()),
			nil,
		},
		{
			"AnyTypeAcceptsNoType",
			"",
			jwt.NewVerificationConfig(jwt.WithAnyType()),
			nil,
		},
		{
			"AnyTypeAfterExpectedTypeRemovesTheCheck",
			"at+jwt",
			jwt.NewVerificationConfig(jwt.WithExpectedType("dpop+jwt"), jwt.WithAnyType()),
			nil,
		},
		{
			"ExpectedTypeAfterAnyTypeRestoresTheCheck",
			"at+jwt",
			jwt.NewVerificationConfig(jwt.WithAnyType(), jwt.WithExpectedType("dpop+jwt")),
			jwt.ErrUnexpectedType,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token := unmarshalToken(t, compactWithHeader(
				t, signingKey, &header.Header{Type: testCase.mediaType, Algorithm: jwa.HS256()},
			))

			err := token.Verify(t.Context(), jwk.NewKeySet(signingKey), testCase.config)
			if !errors.Is(err, testCase.expectedError) {
				t.Errorf("got error %v, want %v", err, testCase.expectedError)
			}
		})
	}
}

func generalToken(t *testing.T, signingKeys []*jwk.Key, headers []*header.Header) string {
	t.Helper()

	signatures := make([]string, 0, len(headers))

	for i, protectedHeader := range headers {
		encodedHeader, signature := signWithHeader(t, signingKeys[i], protectedHeader)
		signatures = append(
			signatures, `{"protected":"`+encodedHeader+`","signature":"`+signature+`"}`,
		)
	}

	return `{"payload":"` + strings.Split(signedToken, ".")[1] +
		`","signatures":[` + strings.Join(signatures, ",") + `]}`
}

const otherSymmetricKeyMaterial = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAoq"

func TestTypeComesFromTheSignatureThatVerified(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)
	unknownKey := key(t, otherSymmetricKeyMaterial)

	for _, testCase := range []struct {
		name string

		unverifiedType string
		verifiedType   string

		expectedError error
	}{
		{
			"TheVerifyingSignatureDecides", "dpop+jwt", "at+jwt", nil,
		},
		{
			"AnUnverifiedSignatureCannotSupplyTheType", "at+jwt", "dpop+jwt", jwt.ErrUnexpectedType,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			token := new(jwt.Token)
			if err := json.Unmarshal([]byte(generalToken(t,
				[]*jwk.Key{unknownKey, signingKey},
				[]*header.Header{
					{Type: testCase.unverifiedType, Algorithm: jwa.HS256()},
					{Type: testCase.verifiedType, Algorithm: jwa.HS256()},
				},
			)), token); err != nil {
				t.Fatalf("cannot decode token: %v", err)
			}

			err := token.Verify(
				t.Context(),
				jwk.NewKeySet(signingKey),
				jwt.NewVerificationConfig(jwt.WithExpectedType("at+jwt")),
			)
			if !errors.Is(err, testCase.expectedError) {
				t.Errorf("got error %v, want %v", err, testCase.expectedError)
			}
		})
	}
}

func TestAllSignaturesCheckEachType(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	for _, testCase := range []struct {
		name          string
		mediaTypes    []string
		expectedError error
	}{
		{"Agree", []string{"at+jwt", "at+jwt"}, nil},
		{"Disagree", []string{"at+jwt", "dpop+jwt"}, jwt.ErrUnexpectedType},
		{"SecondCarriesNone", []string{"at+jwt", ""}, jwt.ErrUnexpectedType},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			headers := make([]*header.Header, 0, len(testCase.mediaTypes))
			signingKeys := make([]*jwk.Key, 0, len(testCase.mediaTypes))

			for _, mediaType := range testCase.mediaTypes {
				headers = append(headers, &header.Header{Type: mediaType, Algorithm: jwa.HS256()})
				signingKeys = append(signingKeys, signingKey)
			}

			token := new(jwt.Token)
			if err := json.Unmarshal(
				[]byte(generalToken(t, signingKeys, headers)), token,
			); err != nil {
				t.Fatalf("cannot decode token: %v", err)
			}

			err := token.Verify(
				t.Context(),
				jwk.NewKeySet(signingKey),
				jwt.NewVerificationConfig(
					jwt.WithExpectedType("at+jwt"), jwt.WithAllSignatures(),
				),
			)
			if !errors.Is(err, testCase.expectedError) {
				t.Errorf("got error %v, want %v", err, testCase.expectedError)
			}
		})
	}
}

type memoryIDStore struct {
	seen map[string]bool
	err  error

	expirations map[string]*time.Time
}

func newMemoryIDStore() *memoryIDStore {
	return &memoryIDStore{seen: map[string]bool{}, expirations: map[string]*time.Time{}}
}

func (store *memoryIDStore) Record(
	_ context.Context, id string, expiration *time.Time,
) (bool, error) {
	if store.err != nil {
		return false, store.err
	}

	if store.seen[id] {
		return false, nil
	}

	store.seen[id] = true
	store.expirations[id] = expiration

	return true, nil
}

func TestReplayCheck(t *testing.T) {
	signingKey := key(t, symmetricKeyMaterial)

	t.Run("SecondUseIsRejected", func(t *testing.T) {
		store := newMemoryIDStore()
		config := jwt.NewVerificationConfig(jwt.WithReplayCheck(store))

		token := newToken(
			t, jwt.WithID("token-1"), jwt.WithSignature(jwa.HS256(), signingKey),
		)

		encodedToken, err := token.Marshal()
		if err != nil {
			t.Fatalf("cannot encode token: %v", err)
		}

		if err := unmarshalToken(t, encodedToken).Verify(
			t.Context(), jwk.NewKeySet(signingKey), config,
		); err != nil {
			t.Fatalf("the first use failed: %v", err)
		}

		if err := unmarshalToken(t, encodedToken).Verify(
			t.Context(), jwk.NewKeySet(signingKey), config,
		); !errors.Is(err, jwt.ErrReplayedToken) {
			t.Errorf("got error %v, want %v", err, jwt.ErrReplayedToken)
		}

		expiration, ok := store.expirations["token-1"]
		if !ok {
			t.Fatal("the store recorded no expiration")
		}

		if expiration == nil || !expiration.Equal(expirationTime) {
			t.Errorf("got expiration %v, want %v", expiration, expirationTime)
		}
	})

	t.Run("MissingIDIsRejected", func(t *testing.T) {
		token := newToken(t, jwt.WithSignature(jwa.HS256(), signingKey))

		if err := token.Verify(
			t.Context(),
			jwk.NewKeySet(signingKey),
			jwt.NewVerificationConfig(jwt.WithReplayCheck(newMemoryIDStore())),
		); !errors.Is(err, jwt.ErrMissingRequiredClaim) {
			t.Errorf("got error %v, want %v", err, jwt.ErrMissingRequiredClaim)
		}
	})

	t.Run("StoreErrorStopsVerification", func(t *testing.T) {
		storeError := errors.New("the store is unreachable")
		store := newMemoryIDStore()
		store.err = storeError

		token := newToken(
			t, jwt.WithID("token-2"), jwt.WithSignature(jwa.HS256(), signingKey),
		)

		err := token.Verify(
			t.Context(), jwk.NewKeySet(signingKey), jwt.NewVerificationConfig(jwt.WithReplayCheck(store)),
		)
		if !errors.Is(err, storeError) {
			t.Errorf("got error %v, want %v", err, storeError)
		}

		if errors.Is(err, jwt.ErrReplayedToken) {
			t.Errorf("got %v, want an error that is not a replay", err)
		}
	})

	t.Run("ARejectedTokenDoesNotUseUpItsID", func(t *testing.T) {
		store := newMemoryIDStore()
		config := jwt.NewVerificationConfig(
			jwt.WithReplayCheck(store), jwt.WithExpectedIssuer("jane"),
		)

		token := newToken(
			t, jwt.WithID("token-3"), jwt.WithSignature(jwa.HS256(), signingKey),
		)

		if err := token.Verify(
			t.Context(), jwk.NewKeySet(signingKey), config,
		); !errors.Is(err, jwt.ErrUnexpectedIssuer) {
			t.Fatalf("got error %v, want %v", err, jwt.ErrUnexpectedIssuer)
		}

		if store.seen["token-3"] {
			t.Error("the store recorded the identifier of a token that verification rejected")
		}
	})
}
