package jwe_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
)

type wrappingPair struct {
	algorithm             jwa.Algorithm
	first, second         any
	firstKey, secondKey   any
	skipCompactComparison bool
}

func wrappingPairs(t *testing.T) []wrappingPair {
	t.Helper()

	symmetric := func(algorithm jwa.Algorithm, size int) wrappingPair {
		first := bytes.Repeat([]byte{7}, size)
		second := bytes.Repeat([]byte{9}, size)

		return wrappingPair{algorithm: algorithm, first: first, second: second, firstKey: first, secondKey: second}
	}

	pairs := []wrappingPair{
		symmetric(jwa.A128KW(), 16),
		symmetric(jwa.A192KW(), 24),
		symmetric(jwa.A256KW(), 32),

		func() wrappingPair { p := symmetric(jwa.A128GCMKW(), 16); p.skipCompactComparison = true; return p }(),
		func() wrappingPair { p := symmetric(jwa.A192GCMKW(), 24); p.skipCompactComparison = true; return p }(),
		func() wrappingPair { p := symmetric(jwa.A256GCMKW(), 32); p.skipCompactComparison = true; return p }(),
	}

	for _, passwordBased := range []jwa.Algorithm{
		jwa.PBES2HS256A128KW(), jwa.PBES2HS384A192KW(), jwa.PBES2HS512A256KW(),
	} {
		first := []byte("entrap o'er the arm the wily bird")
		second := []byte("a second party's altogether different password")

		pairs = append(pairs, wrappingPair{
			algorithm:             passwordBased,
			first:                 first,
			second:                second,
			firstKey:              first,
			secondKey:             second,
			skipCompactComparison: true,
		})
	}

	for _, agreement := range []jwa.Algorithm{jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW()} {
		pairs = append(pairs, wrappingPair{
			algorithm: agreement,
			first:     &agreementKey.PublicKey,
			second:    &secondAgreementKey.PublicKey,
			firstKey:  agreementKey,
			secondKey: secondAgreementKey,

			skipCompactComparison: true,
		})
	}

	for _, rsaAlgorithm := range []jwa.Algorithm{jwa.RSAOAEP(), jwa.RSAOAEP256()} {
		pairs = append(pairs, wrappingPair{
			algorithm: rsaAlgorithm,
			first:     &rsaKey.PublicKey,
			second:    &secondRSAKey.PublicKey,
			firstKey:  rsaKey,
			secondKey: secondRSAKey,

			skipCompactComparison: true,
		})
	}

	return pairs
}

var (
	secondAgreementKey *ecdsa.PrivateKey
	secondRSAKey       *rsa.PrivateKey
)

func init() {
	var err error

	if secondAgreementKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(err)
	}

	if secondRSAKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
}

func encryptTo(t *testing.T, pair wrappingPair, encryption jwa.ContentEncrypter) *jwe.Message {
	t.Helper()

	message := &jwe.Message{
		ProtectedHeader: &header.Header{
			Type:                "JWT",
			Algorithm:           pair.algorithm,
			EncryptionAlgorithm: encryption,
		},
	}

	err := message.EncryptTo(
		[]byte(plaintext),
		jwe.RecipientKey{Key: pair.first},
		jwe.RecipientKey{Key: pair.second},
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	return message
}

func TestEveryRecipientDecrypts(t *testing.T) {
	for _, encryption := range contentEncryptionAlgorithms {
		t.Run(encryption.String(), func(t *testing.T) {
			for _, pair := range wrappingPairs(t) {
				t.Run(pair.algorithm.String(), func(t *testing.T) {
					message := encryptTo(t, pair, encryption)

					if len(message.Recipients) != 2 {
						t.Fatalf("got %d recipients, want 2", len(message.Recipients))
					}

					for name, key := range map[string]any{"first": pair.firstKey, "second": pair.secondKey} {
						decrypted, err := message.Decrypt(key)
						if err != nil {
							t.Errorf("%s recipient cannot decrypt: %v", name, err)

							continue
						}

						if string(decrypted) != plaintext {
							t.Errorf("%s recipient got %q, want %q", name, decrypted, plaintext)
						}
					}
				})
			}
		})
	}
}

func TestRecipientsShareOneCiphertext(t *testing.T) {
	for _, encryption := range contentEncryptionAlgorithms {
		t.Run(encryption.String(), func(t *testing.T) {
			pair := wrappingPairs(t)[0]

			one := &jwe.Message{
				ProtectedHeader: &header.Header{Algorithm: pair.algorithm, EncryptionAlgorithm: encryption},
			}
			if err := one.EncryptTo([]byte(plaintext), jwe.RecipientKey{Key: pair.first}); err != nil {
				t.Fatalf("cannot encrypt to one: %v", err)
			}

			two := encryptTo(t, pair, encryption)

			if len(one.Ciphertext) != len(two.Ciphertext) {
				t.Errorf(
					"a second recipient changed the ciphertext length: %d to %d",
					len(one.Ciphertext), len(two.Ciphertext),
				)
			}

			if len(one.AuthenticationTag) != len(two.AuthenticationTag) {
				t.Errorf(
					"a second recipient changed the tag length: %d to %d",
					len(one.AuthenticationTag), len(two.AuthenticationTag),
				)
			}

			if len(two.InitializationVector) != encryption.IVSize() {
				t.Errorf("got a %d-octet IV, want %d", len(two.InitializationVector), encryption.IVSize())
			}
		})
	}
}

func TestEncryptedKeyMatchesTheCompactSerialization(t *testing.T) {
	for _, encryption := range contentEncryptionAlgorithms {
		t.Run(encryption.String(), func(t *testing.T) {
			for _, pair := range wrappingPairs(t) {
				if pair.skipCompactComparison {
					continue
				}

				t.Run(pair.algorithm.String(), func(t *testing.T) {
					multiple := encryptTo(t, pair, encryption)

					for i, key := range []any{pair.firstKey, pair.secondKey} {
						single := &jwe.Message{
							ProtectedHeader:      multiple.ProtectedHeader,
							Recipients:           []*jwe.Recipient{{EncryptedKey: multiple.Recipients[i].EncryptedKey}},
							InitializationVector: multiple.InitializationVector,
							Ciphertext:           multiple.Ciphertext,
							AuthenticationTag:    multiple.AuthenticationTag,
						}

						compact, err := single.Marshal()
						if err != nil {
							t.Fatalf("recipient %d: cannot serialize compactly: %v", i, err)
						}

						read, err := jwe.Unmarshal(compact)
						if err != nil {
							t.Fatalf("recipient %d: cannot read back: %v", i, err)
						}

						decrypted, err := read.Decrypt(key)
						if err != nil {
							t.Fatalf("recipient %d: the compact form does not decrypt: %v", i, err)
						}

						if string(decrypted) != plaintext {
							t.Errorf("recipient %d: got %q, want %q", i, decrypted, plaintext)
						}
					}
				})
			}
		})
	}
}

func TestDirectModesRefuseASecondRecipient(t *testing.T) {
	encryption := jwa.A128GCM()

	for _, direct := range []struct {
		algorithm   jwa.Algorithm
		first, next any
	}{
		{jwa.Dir(), bytes.Repeat([]byte{7}, encryption.KeySize()), bytes.Repeat([]byte{9}, encryption.KeySize())},
		{jwa.ECDHES(), &agreementKey.PublicKey, &secondAgreementKey.PublicKey},
	} {
		t.Run(direct.algorithm.String(), func(t *testing.T) {
			message := &jwe.Message{
				ProtectedHeader: &header.Header{Algorithm: direct.algorithm, EncryptionAlgorithm: encryption},
			}

			err := message.EncryptTo(
				[]byte(plaintext),
				jwe.RecipientKey{Key: direct.first},
				jwe.RecipientKey{Key: direct.next},
			)

			if !errors.Is(err, jwa.ErrDirectKeyManagement) {
				t.Errorf("got %v, want ErrDirectKeyManagement", err)
			}

			if err := message.Encrypt([]byte(plaintext), direct.first); err != nil {
				t.Errorf("one recipient should still work: %v", err)
			}
		})
	}
}

func TestMultiRecipientUsesTheGeneralSerialization(t *testing.T) {
	message := encryptTo(t, wrappingPairs(t)[0], jwa.A128GCM())

	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("cannot marshal: %v", err)
	}

	var members map[string]jsontext.Value
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("cannot decode: %v", err)
	}

	recipients, ok := members["recipients"]
	if !ok {
		t.Fatal("no recipients member")
	}

	var entries []map[string]jsontext.Value
	if err := json.Unmarshal(recipients, &entries); err != nil {
		t.Fatalf("recipients is not an array of objects: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("got %d array elements, want 2", len(entries))
	}

	for _, forbidden := range []string{"encrypted_key", "header"} {
		if _, present := members[forbidden]; present {
			t.Errorf("the general serialization hoisted %q to the top level", forbidden)
		}
	}

	decoded := new(jwe.Message)
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("cannot round trip: %v", err)
	}

	for i, key := range []any{wrappingPairs(t)[0].firstKey, wrappingPairs(t)[0].secondKey} {
		decrypted, err := decoded.Decrypt(key)
		if err != nil {
			t.Errorf("recipient %d cannot decrypt after a round trip: %v", i, err)

			continue
		}

		if string(decrypted) != plaintext {
			t.Errorf("recipient %d got %q, want %q", i, decrypted, plaintext)
		}
	}
}

func TestEncryptToRequiresARecipient(t *testing.T) {
	message := &jwe.Message{
		ProtectedHeader: &header.Header{Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM()},
	}

	if err := message.EncryptTo([]byte(plaintext)); !errors.Is(err, jwe.ErrMalformedMessage) {
		t.Errorf("got %v, want ErrMalformedMessage", err)
	}
}

func TestRecipientsGetDistinctKeyParameters(t *testing.T) {
	for _, pair := range []wrappingPair{
		{
			algorithm: jwa.ECDHESA128KW(),
			first:     &agreementKey.PublicKey, second: &secondAgreementKey.PublicKey,
			firstKey: agreementKey, secondKey: secondAgreementKey,
		},
		{
			algorithm: jwa.PBES2HS256A128KW(),
			first:     []byte("one sufficiently long password"),
			second:    []byte("another sufficiently long password"),
			firstKey:  []byte("one sufficiently long password"),
			secondKey: []byte("another sufficiently long password"),
		},
		{
			algorithm: jwa.A128GCMKW(),
			first:     bytes.Repeat([]byte{7}, 16), second: bytes.Repeat([]byte{9}, 16),
			firstKey: bytes.Repeat([]byte{7}, 16), secondKey: bytes.Repeat([]byte{9}, 16),
		},
	} {
		t.Run(pair.algorithm.String(), func(t *testing.T) {
			message := encryptTo(t, pair, jwa.A128GCM())

			encoded := make([]string, 0, len(message.Recipients))

			for i, recipient := range message.Recipients {
				if recipient.Header == nil {
					t.Fatalf("recipient %d has no header to carry its key parameters", i)
				}

				members, err := recipient.Header.Members()
				if err != nil {
					t.Fatalf("recipient %d: %v", i, err)
				}

				if len(members) == 0 {
					t.Fatalf("recipient %d declares no key parameters", i)
				}

				encoded = append(encoded, recipient.Header.String())
			}

			if encoded[0] == encoded[1] {
				t.Errorf("both recipients got identical key parameters: %s", encoded[0])
			}
		})
	}
}

func TestDecryptAllNamesTheEntryThatOpened(t *testing.T) {
	keys := [][]byte{
		bytes.Repeat([]byte{7}, 16),
		bytes.Repeat([]byte{9}, 16),
		bytes.Repeat([]byte{11}, 16),
	}

	message := &jwe.Message{
		ProtectedHeader: &header.Header{Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM()},
	}

	err := message.EncryptTo(
		[]byte(plaintext),
		jwe.RecipientKey{Key: keys[0]},
		jwe.RecipientKey{Key: keys[1]},
		jwe.RecipientKey{Key: keys[2]},
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	for opener := range keys {
		decrypted, outcomes, err := message.DecryptAll(keys[opener])
		if err != nil {
			t.Fatalf("recipient %d cannot decrypt: %v", opener, err)
		}

		if string(decrypted) != plaintext {
			t.Errorf("recipient %d got %q, want %q", opener, decrypted, plaintext)
		}

		if len(outcomes) != len(keys) {
			t.Fatalf("got %d outcomes, want %d", len(outcomes), len(keys))
		}

		for i, outcome := range outcomes {
			if outcome.Succeeded != (i == opener) {
				t.Errorf("key %d: outcome %d reports Succeeded=%v", opener, i, outcome.Succeeded)
			}

			if outcome.Recipient != message.Recipients[i] {
				t.Errorf("key %d: outcome %d describes a different recipient", opener, i)
			}

			if i == opener {
				if outcome.Err != nil {
					t.Errorf("key %d: the entry that opened reports %v", opener, outcome.Err)
				}

				continue
			}

			if !errors.Is(outcome.Err, jwa.ErrDecryptionFailed) {
				t.Errorf("key %d: outcome %d reports %v, want ErrDecryptionFailed", opener, i, outcome.Err)
			}
		}
	}
}

func TestDecryptAllReportsAnUnserviceableRecipient(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)

	message := &jwe.Message{
		ProtectedHeader: &header.Header{EncryptionAlgorithm: jwa.A128GCM()},
	}

	err := message.EncryptTo(
		[]byte(plaintext),
		jwe.RecipientKey{Header: &header.Header{Algorithm: jwa.A128KW()}, Key: key},
		jwe.RecipientKey{Header: &header.Header{Algorithm: jwa.A256KW()}, Key: bytes.Repeat([]byte{9}, 32)},
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("cannot serialize: %v", err)
	}

	rewritten := bytes.Replace(encoded, []byte(`"alg":"A256KW"`), []byte(`"alg":"ECDH-1PU"`), 1)
	if bytes.Equal(rewritten, encoded) {
		t.Fatal("the second recipient's alg was not where it was expected")
	}

	received := new(jwe.Message)
	if err := json.Unmarshal(rewritten, received); err != nil {
		t.Fatalf("cannot parse: %v", err)
	}

	decrypted, outcomes, err := received.DecryptAll(key)
	if err != nil {
		t.Fatalf("cannot decrypt the rewritten message: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}

	if len(outcomes) != 2 {
		t.Fatalf("got %d outcomes, want 2", len(outcomes))
	}

	if !outcomes[0].Succeeded || outcomes[0].Err != nil {
		t.Errorf("the serviceable entry reports (%v, %v)", outcomes[0].Succeeded, outcomes[0].Err)
	}

	if outcomes[1].Succeeded {
		t.Error("the entry naming ECDH-1PU reports success")
	}

	if !errors.Is(outcomes[1].Err, jwa.ErrUnsupportedAlgorithm) {
		t.Errorf("got %v, want ErrUnsupportedAlgorithm", outcomes[1].Err)
	}
}

func TestDecryptAllWithNoKeyThatOpens(t *testing.T) {
	message := &jwe.Message{
		ProtectedHeader: &header.Header{Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM()},
	}

	err := message.EncryptTo(
		[]byte(plaintext),
		jwe.RecipientKey{Key: bytes.Repeat([]byte{7}, 16)},
		jwe.RecipientKey{Key: bytes.Repeat([]byte{9}, 16)},
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	decrypted, outcomes, err := message.DecryptAll(bytes.Repeat([]byte{11}, 16))
	if !errors.Is(err, jwa.ErrDecryptionFailed) {
		t.Errorf("got %v, want ErrDecryptionFailed", err)
	}

	if decrypted != nil {
		t.Errorf("got the plaintext %q alongside the failure, want none", decrypted)
	}

	if len(outcomes) != 2 {
		t.Fatalf("got %d outcomes, want 2", len(outcomes))
	}

	for i, outcome := range outcomes {
		if outcome.Succeeded {
			t.Errorf("outcome %d reports success on a message nothing opened", i)
		}

		if !errors.Is(outcome.Err, jwa.ErrDecryptionFailed) {
			t.Errorf("outcome %d reports %v, want ErrDecryptionFailed", i, outcome.Err)
		}
	}
}

func TestDecryptAllOnAMalformedMessage(t *testing.T) {
	for name, message := range map[string]*jwe.Message{
		"no protected header": {},
		"no enc": {
			ProtectedHeader: &header.Header{Algorithm: jwa.A128KW()},
		},
		"no recipients": {
			ProtectedHeader: &header.Header{Algorithm: jwa.A128KW(), EncryptionAlgorithm: jwa.A128GCM()},
		},
	} {
		decrypted, outcomes, err := message.DecryptAll(bytes.Repeat([]byte{7}, 16))
		if !errors.Is(err, jwe.ErrMalformedMessage) {
			t.Errorf("%s: got %v, want ErrMalformedMessage", name, err)
		}

		if decrypted != nil || outcomes != nil {
			t.Errorf("%s: got (%q, %v) alongside the failure, want nothing", name, decrypted, outcomes)
		}
	}
}

func TestDecryptAllAgreesWithDecrypt(t *testing.T) {
	for _, pair := range wrappingPairs(t) {
		t.Run(pair.algorithm.String(), func(t *testing.T) {
			message := encryptTo(t, pair, jwa.A128GCM())

			for name, key := range map[string]any{"first": pair.firstKey, "second": pair.secondKey} {
				want, wantErr := message.Decrypt(key)

				got, _, gotErr := message.DecryptAll(key)
				if !errors.Is(gotErr, wantErr) && !errors.Is(wantErr, gotErr) {
					t.Errorf("%s: Decrypt gave %v, DecryptAll gave %v", name, wantErr, gotErr)
				}

				if !bytes.Equal(got, want) {
					t.Errorf("%s: Decrypt gave %q, DecryptAll gave %q", name, want, got)
				}
			}
		})
	}

	one := &jwe.Message{
		ProtectedHeader: &header.Header{Algorithm: jwa.Dir(), EncryptionAlgorithm: jwa.A128GCM()},
	}

	if err := one.Encrypt([]byte(plaintext), bytes.Repeat([]byte{7}, 16)); err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	if _, err := one.Decrypt(rsaKey); !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Fatalf("Decrypt gave %v, want ErrInvalidKeyType", err)
	}

	_, outcomes, err := one.DecryptAll(rsaKey)
	if !errors.Is(err, jwa.ErrInvalidKeyType) {
		t.Errorf("DecryptAll gave %v, want ErrInvalidKeyType", err)
	}

	if len(outcomes) != 1 || !errors.Is(outcomes[0].Err, jwa.ErrInvalidKeyType) {
		t.Errorf("got outcomes %v, want one naming ErrInvalidKeyType", outcomes)
	}
}
