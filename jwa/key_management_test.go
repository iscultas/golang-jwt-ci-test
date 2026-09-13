package jwa_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/jwa"
)

type keyManagement struct {
	algorithm interface {
		jwa.KeyEncrypter
		jwa.KeyDecrypter
	}

	encryptionKey func(t *testing.T) any
	decryptionKey func(t *testing.T) any
}

func keyManagementAlgorithms(encryption jwa.ContentEncrypter) []keyManagement {
	sharedKey := func(t *testing.T) any {
		t.Helper()

		return bytes.Repeat([]byte{7}, encryption.KeySize())
	}

	keyEncryptionKey := func(size int) func(t *testing.T) any {
		return func(t *testing.T) any {
			t.Helper()

			return bytes.Repeat([]byte{9}, size)
		}
	}

	rsaPublicKey := func(t *testing.T) any {
		t.Helper()

		return &parsePrivateKey(t, rsaPrivateKeyPem).(*rsa.PrivateKey).PublicKey
	}

	rsaPrivateKey := func(t *testing.T) any {
		t.Helper()

		return parsePrivateKey(t, rsaPrivateKeyPem)
	}

	agreementKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	management := []keyManagement{
		{jwa.Dir(), sharedKey, sharedKey},
		{jwa.RSAOAEP(), rsaPublicKey, rsaPrivateKey},
		{jwa.RSAOAEP256(), rsaPublicKey, rsaPrivateKey},
	}

	for _, agreement := range []*jwa.ECDHESAlgorithm{
		jwa.ECDHES(), jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW(),
	} {
		management = append(management, keyManagement{
			agreement,
			func(_ *testing.T) any { return &agreementKey.PublicKey },
			func(_ *testing.T) any { return agreementKey },
		})
	}

	password := func(t *testing.T) any {
		t.Helper()

		return []byte("entrap o'er the arm the wily bird")
	}

	for _, passwordBased := range []*jwa.PBES2{
		jwa.PBES2HS256A128KW(), jwa.PBES2HS384A192KW(), jwa.PBES2HS512A256KW(),
	} {
		management = append(management, keyManagement{passwordBased, password, password})
	}

	for _, symmetric := range []struct {
		algorithm interface {
			jwa.KeyEncrypter
			jwa.KeyDecrypter
		}
		keySize int
	}{
		{jwa.A128KW(), 16},
		{jwa.A192KW(), 24},
		{jwa.A256KW(), 32},
		{jwa.A128GCMKW(), 16},
		{jwa.A192GCMKW(), 24},
		{jwa.A256GCMKW(), 32},
	} {
		management = append(management, keyManagement{
			symmetric.algorithm,
			keyEncryptionKey(symmetric.keySize),
			keyEncryptionKey(symmetric.keySize),
		})
	}

	return management
}

var contentEncryptionAlgorithms = []jwa.ContentEncrypter{
	jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
	jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
}

func TestKeyManagementRoundTrips(t *testing.T) {
	for _, encryption := range contentEncryptionAlgorithms {
		t.Run(encryption.String(), func(t *testing.T) {
			for _, management := range keyManagementAlgorithms(encryption) {
				t.Run(management.algorithm.String(), func(t *testing.T) {
					parameters := new(jwa.KeyParameters)

					cek, encryptedKey, err := management.algorithm.EncryptKey(
						management.encryptionKey(t), encryption, parameters,
					)
					if err != nil {
						t.Fatalf("cannot encrypt the key: %v", err)
					}

					if len(cek) != encryption.KeySize() {
						t.Fatalf("got a %d-octet CEK, want %d", len(cek), encryption.KeySize())
					}

					decrypted, err := management.algorithm.DecryptKey(
						encryptedKey, management.decryptionKey(t), encryption, parameters,
					)
					if err != nil {
						t.Fatalf("cannot decrypt the key: %v", err)
					}

					if !bytes.Equal(decrypted, cek) {
						t.Errorf("round trip changed the CEK:\n got %x\nwant %x", decrypted, cek)
					}
				})
			}
		})
	}
}

func TestKeyManagementRejectsATamperedEncryptedKey(t *testing.T) {
	encryption := jwa.A256GCM()

	for _, management := range keyManagementAlgorithms(encryption) {
		t.Run(management.algorithm.String(), func(t *testing.T) {
			parameters := new(jwa.KeyParameters)

			_, encryptedKey, err := management.algorithm.EncryptKey(
				management.encryptionKey(t), encryption, parameters,
			)
			if err != nil {
				t.Fatalf("cannot encrypt the key: %v", err)
			}

			tampered := bytes.Clone(encryptedKey)
			if len(tampered) == 0 {
				tampered = []byte{0}
			} else {
				tampered[0] ^= 1
			}

			if _, err := management.algorithm.DecryptKey(
				tampered, management.decryptionKey(t), encryption, parameters,
			); !errors.Is(err, jwa.ErrDecryptionFailed) {
				t.Errorf("got %v, want ErrDecryptionFailed", err)
			}
		})
	}
}

func TestKeyManagementRejectsTheWrongKeyType(t *testing.T) {
	encryption := jwa.A256GCM()

	for _, management := range keyManagementAlgorithms(encryption) {
		t.Run(management.algorithm.String(), func(t *testing.T) {
			if _, _, err := management.algorithm.EncryptKey("not a key", encryption, new(jwa.KeyParameters)); !errors.Is(
				err, jwa.ErrInvalidKeyType,
			) {
				t.Errorf("EncryptKey: got %v, want ErrInvalidKeyType", err)
			}

			if _, err := management.algorithm.DecryptKey(
				nil, "not a key", encryption, new(jwa.KeyParameters),
			); !errors.Is(err, jwa.ErrInvalidKeyType) {
				t.Errorf("DecryptKey: got %v, want ErrInvalidKeyType", err)
			}
		})
	}
}

func TestDirectRejectsAKeyOfTheWrongLength(t *testing.T) {
	for _, encryption := range contentEncryptionAlgorithms {
		t.Run(encryption.String(), func(t *testing.T) {
			for _, size := range []int{encryption.KeySize() - 1, encryption.KeySize() + 1, 0} {
				if _, _, err := jwa.Dir().EncryptKey(
					make([]byte, size), encryption, new(jwa.KeyParameters),
				); !errors.Is(err, jwa.ErrInvalidKeySize) {
					t.Errorf("%d-octet key: got %v, want ErrInvalidKeySize", size, err)
				}
			}
		})
	}
}

func TestRSAESOAEPRejectsAWeakKey(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	for _, algorithm := range []*jwa.RSAESOAEP{jwa.RSAOAEP(), jwa.RSAOAEP256()} {
		t.Run(algorithm.String(), func(t *testing.T) {
			if _, _, err := algorithm.EncryptKey(
				&weakKey.PublicKey, jwa.A128GCM(), new(jwa.KeyParameters),
			); !errors.Is(err, jwa.ErrWeakKey) {
				t.Errorf("EncryptKey: got %v, want ErrWeakKey", err)
			}

			if _, err := algorithm.DecryptKey(
				nil, weakKey, jwa.A128GCM(), new(jwa.KeyParameters),
			); !errors.Is(err, jwa.ErrWeakKey) {
				t.Errorf("DecryptKey: got %v, want ErrWeakKey", err)
			}
		})
	}
}
