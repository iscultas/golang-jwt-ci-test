package jwe_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
)

const plaintext = "The true sign of intelligence is not knowledge but imagination."

type keyPair struct {
	algorithm             jwa.Algorithm
	encryption            jwa.ContentEncrypter
	recipient, recipient2 any
}

func keyPairs(t *testing.T, encryption jwa.ContentEncrypter) []keyPair {
	t.Helper()

	symmetric := func(algorithm jwa.Algorithm, size int) keyPair {
		key := bytes.Repeat([]byte{7}, size)

		return keyPair{algorithm, encryption, key, key}
	}

	pairs := []keyPair{
		symmetric(jwa.Dir(), encryption.KeySize()),
		symmetric(jwa.A128KW(), 16),
		symmetric(jwa.A192KW(), 24),
		symmetric(jwa.A256KW(), 32),
		symmetric(jwa.A128GCMKW(), 16),
		symmetric(jwa.A192GCMKW(), 24),
		symmetric(jwa.A256GCMKW(), 32),
	}

	for _, passwordBased := range []jwa.Algorithm{
		jwa.PBES2HS256A128KW(), jwa.PBES2HS384A192KW(), jwa.PBES2HS512A256KW(),
	} {
		password := []byte("entrap o'er the arm the wily bird")
		pairs = append(pairs, keyPair{passwordBased, encryption, password, password})
	}

	for _, agreement := range []jwa.Algorithm{
		jwa.ECDHES(), jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW(),
	} {
		pairs = append(pairs, keyPair{agreement, encryption, &agreementKey.PublicKey, agreementKey})
	}

	for _, rsaAlgorithm := range []jwa.Algorithm{jwa.RSAOAEP(), jwa.RSAOAEP256()} {
		pairs = append(pairs, keyPair{rsaAlgorithm, encryption, &rsaKey.PublicKey, rsaKey})
	}

	return pairs
}

var (
	agreementKey *ecdsa.PrivateKey
	rsaKey       *rsa.PrivateKey
)

func init() {
	var err error

	if agreementKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(err)
	}

	if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
}

var contentEncryptionAlgorithms = []jwa.ContentEncrypter{
	jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
	jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
}

func encrypt(t *testing.T, pair keyPair) *jwe.Message {
	t.Helper()

	message := &jwe.Message{
		ProtectedHeader: &header.Header{
			Type:                "JWT",
			Algorithm:           pair.algorithm,
			EncryptionAlgorithm: pair.encryption,
		},
	}

	if err := message.Encrypt([]byte(plaintext), pair.recipient); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	return message
}

func TestRoundTripsEveryPairing(t *testing.T) {
	for _, encryption := range contentEncryptionAlgorithms {
		t.Run(encryption.String(), func(t *testing.T) {
			for _, pair := range keyPairs(t, encryption) {
				t.Run(pair.algorithm.String(), func(t *testing.T) {
					encoded, err := encrypt(t, pair).Marshal()
					if err != nil {
						t.Fatalf("cannot serialize: %v", err)
					}

					if parts := strings.Count(encoded, "."); parts != 4 {
						t.Errorf("got %d full stops, want 4", parts)
					}

					message, err := jwe.Unmarshal(encoded)
					if err != nil {
						t.Fatalf("cannot parse: %v", err)
					}

					decrypted, err := message.Decrypt(pair.recipient2)
					if err != nil {
						t.Fatalf("cannot decrypt: %v", err)
					}

					if string(decrypted) != plaintext {
						t.Errorf("got %q, want %q", decrypted, plaintext)
					}
				})
			}
		})
	}
}

func TestRoundTripsThroughJSON(t *testing.T) {
	pair := keyPairs(t, jwa.A256GCM())[0]

	for _, additionalAuthenticatedData := range [][]byte{nil, []byte("application data")} {
		message := encrypt(t, pair)

		if additionalAuthenticatedData != nil {
			message = &jwe.Message{
				ProtectedHeader:             &header.Header{Algorithm: pair.algorithm, EncryptionAlgorithm: pair.encryption},
				AdditionalAuthenticatedData: additionalAuthenticatedData,
			}

			if err := message.Encrypt([]byte(plaintext), pair.recipient); err != nil {
				t.Fatalf("cannot encrypt: %v", err)
			}
		}

		encoded, err := json.Marshal(message)
		if err != nil {
			t.Fatalf("cannot serialize: %v", err)
		}

		decoded := new(jwe.Message)
		if err := json.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("cannot parse: %v", err)
		}

		decrypted, err := decoded.Decrypt(pair.recipient2)
		if err != nil {
			t.Fatalf("cannot decrypt %s: %v", encoded, err)
		}

		if string(decrypted) != plaintext {
			t.Errorf("got %q, want %q", decrypted, plaintext)
		}
	}
}

func TestJSONSerializationIsFlattenedForOneRecipient(t *testing.T) {
	encoded, err := json.Marshal(encrypt(t, keyPairs(t, jwa.A256GCM())[1]))
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	if strings.Contains(string(encoded), `"recipients"`) {
		t.Errorf("got %s, want the flattened form", encoded)
	}

	if !strings.Contains(string(encoded), `"encrypted_key"`) {
		t.Errorf("got %s, want a hoisted encrypted_key", encoded)
	}
}

func TestDecryptRejectsATamperedProtectedHeader(t *testing.T) {
	pair := keyPairs(t, jwa.A256GCM())[0]

	encoded, err := encrypt(t, pair).Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	parts := strings.Split(encoded, ".")

	parts[0] = base64.RawURLEncoding.EncodeToString(
		[]byte(`{"enc":"A256GCM","alg":"dir","typ":"JWT"}`),
	)

	message, err := jwe.Unmarshal(strings.Join(parts, "."))
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	if _, err := message.Decrypt(pair.recipient2); !errors.Is(err, jwa.ErrDecryptionFailed) {
		t.Errorf("got %v, want ErrDecryptionFailed", err)
	}
}

func TestMarshalKeepsTheAuthenticatedProtectedHeader(t *testing.T) {
	pair := keyPairs(t, jwa.A256GCM())[0]
	message := encrypt(t, pair)

	message.ProtectedHeader.KeyID = "added after the tag"

	encoded, err := message.Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	decoded, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	decrypted, err := decoded.Decrypt(pair.recipient2)
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}

	if keyID := decoded.ProtectedHeader.KeyID; keyID != "" {
		t.Errorf("got kid %q in the serialization, want the header that the tag covers", keyID)
	}
}

func TestDecryptFailuresAboutTheCallersOwnKeyStayDistinct(t *testing.T) {
	pair := keyPairs(t, jwa.A256GCM())[0]

	encoded, err := encrypt(t, pair).Marshal()
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	message, err := jwe.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	if _, err := message.Decrypt(rsaKey); !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Errorf("got %v, want ErrInvalidKeyType", err)
	}

	if _, err := message.Decrypt(make([]byte, 16)); !errors.Is(err, jwa.ErrInvalidKeySize) {
		t.Errorf("got %v, want ErrInvalidKeySize", err)
	}
}

func TestDecryptRejectsASignatureAlgorithm(t *testing.T) {
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","enc":"A128GCM"}`))

	encodedCiphertext := base64.RawURLEncoding.EncodeToString([]byte("ciphertext"))

	message, err := jwe.Unmarshal(encodedHeader + "..." + encodedCiphertext + ".")
	if err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	if _, err := message.Decrypt(agreementKey); !errors.Is(err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestStringPanicsWhereMarshalFails(t *testing.T) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("got no panic, want one")
		}

		err, isError := recovered.(error)
		if !isError || !errors.Is(err, jwe.ErrMalformedMessage) {
			t.Errorf("got panic %v, want %v", recovered, jwe.ErrMalformedMessage)
		}
	}()

	_ = new(jwe.Message).String()
}
