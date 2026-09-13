package jwa_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/iscultas/jwt-go/jwa"
)

var exampleUnsignedToken = []byte("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0")

var exampleSecret = []byte("0123456789abcdef0123456789abcdef")

var exampleKey = []byte("0123456789abcdef")

var exampleRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return key
})

func exampleECDSAKey(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	return key
}

func Example() {
	signature, err := jwa.HS256().Sign(exampleUnsignedToken, exampleSecret)
	if err != nil {
		panic(err)
	}

	if err := jwa.HS256().Verify(exampleUnsignedToken, signature, exampleSecret); err != nil {
		panic(err)
	}

	changed := jwa.HS256().Verify([]byte("a different token"), signature, exampleSecret)

	fmt.Println(jwa.HS256(), len(signature), errors.Is(changed, jwa.ErrSignatureMismatch))

	// Output:
	// HS256 32 true
}

func ExampleAlgorithms() {
	names := make([]string, 0, len(jwa.Algorithms()))
	for _, algorithm := range jwa.Algorithms() {
		names = append(names, algorithm.String())
	}

	fmt.Println(strings.Join(names, "\n"))

	// Output:
	// A128CBC-HS256
	// A128GCM
	// A128GCMKW
	// A128KW
	// A192CBC-HS384
	// A192GCM
	// A192GCMKW
	// A192KW
	// A256CBC-HS512
	// A256GCM
	// A256GCMKW
	// A256KW
	// ECDH-ES
	// ECDH-ES+A128KW
	// ECDH-ES+A192KW
	// ECDH-ES+A256KW
	// ES256
	// ES384
	// ES512
	// Ed25519
	// EdDSA
	// HS256
	// HS384
	// HS512
	// ML-DSA-44
	// ML-DSA-65
	// ML-DSA-87
	// PBES2-HS256+A128KW
	// PBES2-HS384+A192KW
	// PBES2-HS512+A256KW
	// PS256
	// PS384
	// PS512
	// RS256
	// RS384
	// RS512
	// RSA-OAEP
	// RSA-OAEP-256
	// RSA1_5
	// dir
	// none
}

func ExampleByName() {
	algorithm, ok := jwa.ByName("ES256")
	if !ok {
		panic("ES256 is not available")
	}

	signer, isSigner := algorithm.(jwa.Signer)
	_, isContentEncrypter := algorithm.(jwa.ContentEncrypter)

	_, available := jwa.ByName("ECDH-1PU")

	fmt.Println(signer, isSigner, isContentEncrypter, available)
	fmt.Println(errors.Is(jwa.UnsupportedAlgorithm("ECDH-1PU"), jwa.ErrUnsupportedAlgorithm))

	// Output:
	// ES256 true false false
	// true
}

func ExampleHS256() {
	signature, err := jwa.HS256().Sign(exampleUnsignedToken, exampleSecret)
	if err != nil {
		panic(err)
	}

	verified := jwa.HS256().Verify(exampleUnsignedToken, signature, exampleSecret)

	_, weak := jwa.HS256().Sign(exampleUnsignedToken, []byte("0123456789abcdef"))
	_, wrongType := jwa.HS256().Sign(exampleUnsignedToken, "a string")

	fmt.Println(verified, errors.Is(weak, jwa.ErrWeakKey), errors.Is(wrongType, jwa.ErrInvalidKeyType))

	// Output:
	// <nil> true true
}

func ExampleES256() {
	key := exampleECDSAKey(elliptic.P256())

	signature, err := jwa.ES256().Sign(exampleUnsignedToken, key)
	if err != nil {
		panic(err)
	}

	verified := jwa.ES256().Verify(exampleUnsignedToken, signature, &key.PublicKey)

	_, wrongCurve := jwa.ES256().Sign(exampleUnsignedToken, exampleECDSAKey(elliptic.P384()))

	fmt.Println(jwa.ES256(), len(signature), verified, errors.Is(wrongCurve, jwa.ErrInvalidKeyType))

	// Output:
	// ES256 64 <nil> true
}

func ExampleEdDSA() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	signature, err := jwa.EdDSA().Sign(exampleUnsignedToken, privateKey)
	if err != nil {
		panic(err)
	}

	verified := jwa.Ed25519().Verify(exampleUnsignedToken, signature, publicKey)

	fmt.Println(jwa.EdDSA(), jwa.Ed25519(), len(signature), verified)

	// Output:
	// EdDSA Ed25519 64 <nil>
}

func ExampleMLDSA44() {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		panic(err)
	}

	signature, err := jwa.MLDSA44().Sign(exampleUnsignedToken, key)
	if err != nil {
		panic(err)
	}

	verified := jwa.MLDSA44().Verify(exampleUnsignedToken, signature, key.PublicKey())

	_, wrongSet := jwa.MLDSA65().Sign(exampleUnsignedToken, key)

	fmt.Println(len(key.PublicKey().Bytes()), len(signature), verified)
	fmt.Println(errors.Is(wrongSet, jwa.ErrInvalidKeyType))

	// Output:
	// 1312 2420 <nil>
	// true
}

func ExampleRS256() {
	key := exampleRSAKey()

	signature, err := jwa.RS256().Sign(exampleUnsignedToken, key)
	if err != nil {
		panic(err)
	}

	verified := jwa.RS256().Verify(exampleUnsignedToken, signature, &key.PublicKey)

	fmt.Println(jwa.RS256(), len(signature), verified)

	// Output:
	// RS256 256 <nil>
}

func ExamplePS256() {
	key := exampleRSAKey()

	first, err := jwa.PS256().Sign(exampleUnsignedToken, key)
	if err != nil {
		panic(err)
	}

	second, err := jwa.PS256().Sign(exampleUnsignedToken, key)
	if err != nil {
		panic(err)
	}

	verified := jwa.PS256().Verify(exampleUnsignedToken, first, &key.PublicKey)

	fmt.Println(jwa.PS256(), len(first), string(first) == string(second), verified)

	// Output:
	// PS256 256 false <nil>
}

func ExampleNone() {
	signature, err := jwa.None().Sign(exampleUnsignedToken, nil)
	if err != nil {
		panic(err)
	}

	forged := jwa.None().Verify([]byte("a token that no signer saw"), nil, nil)

	allowlist := make([]jwa.Algorithm, 0, len(jwa.Algorithms()))

	for _, algorithm := range jwa.Algorithms() {
		if algorithm != jwa.Algorithm(jwa.None()) {
			allowlist = append(allowlist, algorithm)
		}
	}

	fmt.Println(jwa.None(), len(signature), forged, len(allowlist) == len(jwa.Algorithms())-1)

	// Output:
	// none 0 <nil> true
}

func ExampleA128GCM() {
	encryption := jwa.A128GCM()

	cek, err := jwa.GenerateContentEncryptionKey(encryption)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, encryption.IVSize())
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}

	additionalAuthenticatedData := []byte("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0")

	ciphertext, tag, err := encryption.Encrypt(
		[]byte("the claims"), cek, iv, additionalAuthenticatedData,
	)
	if err != nil {
		panic(err)
	}

	plaintext, err := encryption.Decrypt(ciphertext, cek, iv, additionalAuthenticatedData, tag)
	if err != nil {
		panic(err)
	}

	_, changed := encryption.Decrypt(ciphertext, cek, iv, []byte("a different header"), tag)

	fmt.Println(encryption, encryption.KeySize(), encryption.IVSize(), len(tag))
	fmt.Println(string(plaintext), errors.Is(changed, jwa.ErrDecryptionFailed))

	// Output:
	// A128GCM 16 12 16
	// the claims true
}

func ExampleA128CBCHS256() {
	encryption := jwa.A128CBCHS256()

	cek, err := jwa.GenerateContentEncryptionKey(encryption)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, encryption.IVSize())
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}

	ciphertext, tag, err := encryption.Encrypt([]byte("the claims"), cek, iv, nil)
	if err != nil {
		panic(err)
	}

	plaintext, err := encryption.Decrypt(ciphertext, cek, iv, nil, tag)
	if err != nil {
		panic(err)
	}

	_, _, wrongSize := encryption.Encrypt([]byte("the claims"), cek[:16], iv, nil)

	fmt.Println(encryption, encryption.KeySize(), encryption.IVSize(), len(tag))
	fmt.Println(string(plaintext), errors.Is(wrongSize, jwa.ErrInvalidKeySize))

	// Output:
	// A128CBC-HS256 32 16 16
	// the claims true
}

func ExampleGenerateContentEncryptionKey() {
	encryption := jwa.A128GCM()

	cek, err := jwa.GenerateContentEncryptionKey(encryption)
	if err != nil {
		panic(err)
	}

	first, err := jwa.A128KW().WrapKey(cek, exampleKey, encryption, new(jwa.KeyParameters))
	if err != nil {
		panic(err)
	}

	second, err := jwa.A128KW().WrapKey(cek, []byte("fedcba9876543210"), encryption, new(jwa.KeyParameters))
	if err != nil {
		panic(err)
	}

	fmt.Println(len(cek) == encryption.KeySize(), len(first), len(second))

	// Output:
	// true 24 24
}

func ExampleA128KW() {
	encryption := jwa.A128GCM()

	cek, encryptedKey, err := jwa.A128KW().EncryptKey(exampleKey, encryption, new(jwa.KeyParameters))
	if err != nil {
		panic(err)
	}

	received, err := jwa.A128KW().DecryptKey(encryptedKey, exampleKey, encryption, new(jwa.KeyParameters))
	if err != nil {
		panic(err)
	}

	_, _, wrongSize := jwa.A128KW().EncryptKey(make([]byte, 32), encryption, new(jwa.KeyParameters))

	fmt.Println(jwa.A128KW(), len(cek), len(encryptedKey), string(received) == string(cek))
	fmt.Println(errors.Is(wrongSize, jwa.ErrInvalidKeySize))

	// Output:
	// A128KW 16 24 true
	// true
}

func ExampleA128GCMKW() {
	encryption := jwa.A128GCM()
	parameters := new(jwa.KeyParameters)

	cek, encryptedKey, err := jwa.A128GCMKW().EncryptKey(exampleKey, encryption, parameters)
	if err != nil {
		panic(err)
	}

	received, err := jwa.A128GCMKW().DecryptKey(encryptedKey, exampleKey, encryption, parameters)
	if err != nil {
		panic(err)
	}

	other := new(jwa.KeyParameters)
	if _, err := jwa.A128GCMKW().WrapKey(cek, exampleKey, encryption, other); err != nil {
		panic(err)
	}

	fmt.Println(jwa.A128GCMKW(), len(parameters.InitializationVector), len(parameters.AuthenticationTag))
	fmt.Println(
		string(received) == string(cek),
		string(parameters.InitializationVector) == string(other.InitializationVector),
	)

	// Output:
	// A128GCMKW 12 16
	// true false
}

func ExampleECDHES() {
	encryption := jwa.A128GCM()
	recipientKey := exampleECDSAKey(elliptic.P256())

	parameters := new(jwa.KeyParameters)

	parameters.AgreementPartyUInfo = []byte("alice")
	parameters.AgreementPartyVInfo = []byte("bob")

	cek, encryptedKey, err := jwa.ECDHES().EncryptKey(
		&recipientKey.PublicKey, encryption, parameters,
	)
	if err != nil {
		panic(err)
	}

	received, err := jwa.ECDHES().DecryptKey(encryptedKey, recipientKey, encryption, parameters)
	if err != nil {
		panic(err)
	}

	wrapped := new(jwa.KeyParameters)
	_, wrappedKey, err := jwa.ECDHESA128KW().EncryptKey(&recipientKey.PublicKey, encryption, wrapped)
	if err != nil {
		panic(err)
	}

	fmt.Println(jwa.ECDHES(), len(cek), len(encryptedKey), parameters.EphemeralPublicKey != nil)
	fmt.Println(string(received) == string(cek), jwa.ECDHESA128KW(), len(wrappedKey))

	// Output:
	// ECDH-ES 16 0 true
	// true ECDH-ES+A128KW 24
}

func ExampleRSAOAEP() {
	encryption := jwa.A128GCM()
	key := exampleRSAKey()

	cek, encryptedKey, err := jwa.RSAOAEP256().EncryptKey(
		&key.PublicKey, encryption, new(jwa.KeyParameters),
	)
	if err != nil {
		panic(err)
	}

	received, err := jwa.RSAOAEP256().DecryptKey(
		encryptedKey, key, encryption, new(jwa.KeyParameters),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(jwa.RSAOAEP(), jwa.RSAOAEP256(), len(cek), len(encryptedKey))
	fmt.Println(string(received) == string(cek))

	// Output:
	// RSA-OAEP RSA-OAEP-256 16 256
	// true
}

func ExampleRSA15() {
	key := exampleRSAKey()
	encryption := jwa.A128GCM()

	_, isKeyEncrypter := any(jwa.RSA15()).(jwa.KeyEncrypter)

	encryptedKey := make([]byte, key.Size())

	cek, err := jwa.RSA15().DecryptKey(encryptedKey, key, encryption, new(jwa.KeyParameters))
	if err != nil {
		panic(err)
	}

	tooLarge := bytes.Repeat([]byte{0xff}, key.Size())

	_, err = jwa.RSA15().DecryptKey(tooLarge, key, encryption, new(jwa.KeyParameters))

	fmt.Println(jwa.RSA15(), isKeyEncrypter, len(cek) == encryption.KeySize())
	fmt.Println(errors.Is(err, jwa.ErrDecryptionFailed))

	// Output:
	// RSA1_5 false true
	// true
}

func ExamplePBES2HS256A128KW() {
	encryption := jwa.A128GCM()
	password := []byte("a password of the recommended length")

	parameters := new(jwa.KeyParameters)

	cek, encryptedKey, err := jwa.PBES2HS256A128KW().EncryptKey(password, encryption, parameters)
	if err != nil {
		panic(err)
	}

	received, err := jwa.PBES2HS256A128KW().DecryptKey(
		encryptedKey, password, encryption, parameters,
	)
	if err != nil {
		panic(err)
	}

	_, _, weak := jwa.PBES2HS256A128KW().EncryptKey([]byte("short"), encryption, new(jwa.KeyParameters))

	_, few := jwa.PBES2HS256A128KW().DecryptKey(encryptedKey, password, encryption, &jwa.KeyParameters{
		PBES2SaltInput: parameters.PBES2SaltInput,
		PBES2Count:     100,
	})

	fmt.Println(jwa.PBES2HS256A128KW(), len(cek), len(encryptedKey), len(parameters.PBES2SaltInput))
	fmt.Println(
		string(received) == string(cek),
		errors.Is(weak, jwa.ErrWeakPassword),
		errors.Is(few, jwa.ErrInsufficientIterationCount),
	)

	// Output:
	// PBES2-HS256+A128KW 16 24 16
	// true true true
}

func ExampleDir() {
	encryption := jwa.A128GCM()

	agreedKey := make([]byte, encryption.KeySize())

	cek, encryptedKey, err := jwa.Dir().EncryptKey(agreedKey, encryption, new(jwa.KeyParameters))
	if err != nil {
		panic(err)
	}

	received, err := jwa.Dir().DecryptKey(encryptedKey, agreedKey, encryption, new(jwa.KeyParameters))
	if err != nil {
		panic(err)
	}

	_, _, wrongSize := jwa.Dir().EncryptKey(make([]byte, 24), encryption, new(jwa.KeyParameters))

	_, isWrapper := jwa.Algorithm(jwa.Dir()).(jwa.KeyWrapper)

	fmt.Println(jwa.Dir(), len(cek), len(encryptedKey), string(received) == string(cek))
	fmt.Println(isWrapper, errors.Is(wrongSize, jwa.ErrInvalidKeySize))

	// Output:
	// dir 16 0 true
	// false true
}
