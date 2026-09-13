package jwk_test

import (
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

const mldsaSeed = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func mldsaPrivateKey(t testing.TB) *mldsa.PrivateKey {
	t.Helper()

	seed, err := base64.RawURLEncoding.DecodeString(mldsaSeed)
	if err != nil {
		t.Fatalf("cannot decode seed: %v", err)
	}

	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("cannot make private key: %v", err)
	}

	return privateKey
}

func mldsaKey(t testing.TB) *jwk.Key {
	t.Helper()

	return jwk.NewKey(mldsaPrivateKey(t))
}

func mldsaPublicKeyJwk(t testing.TB) *jwk.Key {
	t.Helper()

	return jwk.NewKey(mldsaPrivateKey(t).PublicKey())
}

func mldsaPublicKeyValue(t testing.TB) string {
	t.Helper()

	return base64.RawURLEncoding.EncodeToString(mldsaPrivateKey(t).PublicKey().Bytes())
}

func encodedMLDSAKey(t testing.TB) string {
	t.Helper()

	return fmt.Sprintf(
		`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"priv":%q}`, mldsaPublicKeyValue(t), mldsaSeed,
	)
}

func encodedMLDSAPublicKey(t testing.TB) string {
	t.Helper()

	return fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q}`, mldsaPublicKeyValue(t))
}

func TestNewKeyGivesAKPItsAlgorithm(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		key       *jwk.Key
		algorithm jwa.Algorithm
	}{
		{"Private", mldsaKey(t), jwa.MLDSA44()},
		{"Public", mldsaPublicKeyJwk(t), jwa.MLDSA44()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if keyType := testCase.key.Type(); keyType != jwk.AlgorithmKeyPair {
				t.Errorf("got kty %s, want %s", keyType, jwk.AlgorithmKeyPair)
			}

			if algorithm := testCase.key.Algorithm(); algorithm != testCase.algorithm {
				t.Errorf("got alg %v, want %v", algorithm, testCase.algorithm)
			}
		})
	}
}

func TestEncodingMismatchedAKPAlgorithm(t *testing.T) {
	key := jwk.NewKey(mldsaPrivateKey(t), jwk.WithAlgorithm(jwa.MLDSA87()))

	if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrMalformedKey) {
		t.Errorf("got error %v, want %v", err, jwk.ErrMalformedKey)
	}
}

func TestZeroMLDSAKeyIsUnsupported(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		material any
	}{
		{"PrivateKey", new(mldsa.PrivateKey)},
		{"PublicKey", new(mldsa.PublicKey)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key := jwk.NewKey(testCase.material)

			if keyType := key.Type(); keyType != "" {
				t.Errorf("got kty %q, want an empty one", keyType)
			}

			if _, err := json.Marshal(key); !errors.Is(err, jwk.ErrUnsupportedKeyType) {
				t.Errorf("encoding: got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
			}

			if _, err := key.Thumbprint(crypto.SHA256); !errors.Is(err, jwk.ErrUnsupportedKeyType) {
				t.Errorf("thumbprint: got error %v, want %v", err, jwk.ErrUnsupportedKeyType)
			}
		})
	}

	if publicKey := jwk.NewKey(new(mldsa.PrivateKey)).Public(); publicKey != nil {
		t.Errorf("got %v, want nil", publicKey)
	}
}

func TestDecodingMalformedAKP(t *testing.T) {
	publicKey := mldsaPublicKeyValue(t)

	const mismatchedSeed = "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	for name, testCase := range map[string]struct {
		encodedKey string
		err        error
	}{
		"MissingAlgorithm": {
			fmt.Sprintf(`{"kty":"AKP","pub":%q}`, publicKey), &jwk.MissingRequiredParameterError{},
		},
		"MissingPub": {`{"kty":"AKP","alg":"ML-DSA-44"}`, &jwk.MissingRequiredParameterError{}},

		"OtherAlgorithm": {
			fmt.Sprintf(`{"kty":"AKP","alg":"ES256","pub":%q}`, publicKey), jwa.ErrUnsupportedAlgorithm,
		},
		"UnregisteredAlgorithm": {
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-11","pub":%q}`, publicKey), jwa.ErrUnsupportedAlgorithm,
		},

		"ShortPub": {`{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA"}`, jwk.ErrMalformedKey},

		"PubOfOtherParameterSet": {
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-65","pub":%q}`, publicKey), jwk.ErrMalformedKey,
		},

		"ShortPriv": {
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"priv":"AAAA"}`, publicKey),
			jwk.ErrMalformedKey,
		},
		"MismatchedPriv": {
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"priv":%q}`, publicKey, mismatchedSeed),
			jwk.ErrMalformedKey,
		},

		"NonBase64Pub": {`{"kty":"AKP","alg":"ML-DSA-44","pub":"!"}`, base64.CorruptInputError(0)},
		"NonBase64Priv": {
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"priv":"!"}`, publicKey),
			base64.CorruptInputError(0),
		},
	} {
		t.Run(name, func(t *testing.T) {
			key := new(jwk.Key)

			requireDecodingError(t, json.Unmarshal([]byte(testCase.encodedKey), key), testCase.err)

			if key.Material() != nil {
				t.Errorf("got material %v, want none", key.Material())
			}
		})
	}
}

func TestAKPMaterialType(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		encodedKey   string
		materialType string
	}{
		{"Private", encodedMLDSAKey(t), "*mldsa.PrivateKey"},
		{"Public", encodedMLDSAPublicKey(t), "*mldsa.PublicKey"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			key := new(jwk.Key)
			if err := json.Unmarshal([]byte(testCase.encodedKey), key); err != nil {
				t.Fatalf("cannot decode key: %v", err)
			}

			if materialType := fmt.Sprintf("%T", key.Material()); materialType != testCase.materialType {
				t.Errorf("got material %s, want %s", materialType, testCase.materialType)
			}
		})
	}
}

func TestAKPPublic(t *testing.T) {
	key := new(jwk.Key)
	if err := json.Unmarshal([]byte(encodedMLDSAKey(t)), key); err != nil {
		t.Fatalf("cannot decode key: %v", err)
	}

	if !key.IsPrivate() {
		t.Error("got a public key, want a private one")
	}

	publicKey := key.Public()

	if publicKey.IsPrivate() {
		t.Error("got a private key from Public, want a public one")
	}

	encodedPublicKey, err := json.Marshal(publicKey)
	if err != nil {
		t.Fatalf("cannot encode key: %v", err)
	}

	if string(encodedPublicKey) != encodedMLDSAPublicKey(t) {
		t.Errorf("got %s, want %s", encodedPublicKey, encodedMLDSAPublicKey(t))
	}
}
