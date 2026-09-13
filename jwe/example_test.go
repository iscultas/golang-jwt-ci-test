package jwe_test

import (
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
)

var exampleKey = []byte("0123456789abcdef")

var exampleSecondKey = []byte("fedcba9876543210")

func Example() {
	message := &jwe.Message{
		ProtectedHeader: &header.Header{
			Algorithm:           jwa.Dir(),
			EncryptionAlgorithm: jwa.A256GCM(),
		},
	}

	agreedKey := make([]byte, 32)

	if err := message.Encrypt([]byte("the claims"), agreedKey); err != nil {
		panic(err)
	}

	serialized, err := message.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwe.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	plaintext, err := received.Decrypt(agreedKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext), len(received.Recipients[0].EncryptedKey))

	// Output:
	// the claims 0
}

func ExampleMessage() {
	message := &jwe.Message{
		ProtectedHeader: &header.Header{
			Algorithm:           jwa.A128KW(),
			EncryptionAlgorithm: jwa.A128GCM(),
		},
		AdditionalAuthenticatedData: []byte("https://api.example"),
	}

	if err := message.Encrypt([]byte("the claims"), exampleKey); err != nil {
		panic(err)
	}

	_, compact := message.Marshal()

	document, err := json.Marshal(message)
	if err != nil {
		panic(err)
	}

	received := new(jwe.Message)
	if err := json.Unmarshal(document, received); err != nil {
		panic(err)
	}

	plaintext, err := received.Decrypt(exampleKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(errors.Is(compact, jwe.ErrMalformedMessage))
	fmt.Println(string(plaintext), string(received.AdditionalAuthenticatedData))

	// Output:
	// true
	// the claims https://api.example
}

func ExampleUnmarshal() {
	message := &jwe.Message{
		ProtectedHeader: &header.Header{
			Algorithm:           jwa.A128KW(),
			EncryptionAlgorithm: jwa.A128GCM(),
		},
	}

	if err := message.Encrypt([]byte("the claims"), exampleKey); err != nil {
		panic(err)
	}

	serialized, err := message.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwe.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	plaintext, err := received.Decrypt(exampleKey)
	if err != nil {
		panic(err)
	}

	_, tooFewParts := jwe.Unmarshal("a.b.c")
	_, zero := new(jwe.Message).Decrypt(exampleKey)

	fmt.Println(string(plaintext), received.ProtectedHeader.Algorithm)
	fmt.Println(errors.Is(tooFewParts, jwe.ErrMalformedMessage), errors.Is(zero, jwe.ErrMalformedMessage))

	// Output:
	// the claims A128KW
	// true true
}

func ExampleMessage_EncryptTo() {
	message := &jwe.Message{
		ProtectedHeader: &header.Header{
			Algorithm:           jwa.A128KW(),
			EncryptionAlgorithm: jwa.A128GCM(),
		},
	}

	first := new(header.Header)
	header.WithKeyID("alice")(first)

	second := new(header.Header)
	header.WithKeyID("bob")(second)

	if err := message.EncryptTo(
		[]byte("the claims"),
		jwe.RecipientKey{Header: first, Key: exampleKey},
		jwe.RecipientKey{Header: second, Key: exampleSecondKey},
	); err != nil {
		panic(err)
	}

	document, err := json.Marshal(message)
	if err != nil {
		panic(err)
	}

	received := new(jwe.Message)
	if err := json.Unmarshal(document, received); err != nil {
		panic(err)
	}

	plaintext, err := received.Decrypt(exampleSecondKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(received.Recipients))
	for _, recipient := range received.Recipients {
		fmt.Println(recipient.Header.KeyID, len(recipient.EncryptedKey))
	}

	fmt.Println(string(plaintext))

	// Output:
	// 2
	// alice 24
	// bob 24
	// the claims
}

func ExampleMessage_DecryptAll() {
	message := &jwe.Message{
		ProtectedHeader: &header.Header{
			Algorithm:           jwa.A128KW(),
			EncryptionAlgorithm: jwa.A128GCM(),
		},
	}

	if err := message.EncryptTo(
		[]byte("the claims"),
		jwe.RecipientKey{Key: exampleKey},
		jwe.RecipientKey{Key: exampleSecondKey},
	); err != nil {
		panic(err)
	}

	plaintext, outcomes, err := message.DecryptAll(exampleSecondKey)
	if err != nil {
		panic(err)
	}

	for _, outcome := range outcomes {
		fmt.Println(outcome.Succeeded, errors.Is(outcome.Err, jwa.ErrDecryptionFailed))
	}

	fmt.Println(string(plaintext))

	// Output:
	// false true
	// true false
	// the claims
}
