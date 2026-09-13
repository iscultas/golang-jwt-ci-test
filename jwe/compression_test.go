package jwe_test

import (
	"bytes"
	"compress/flate"
	"errors"
	"testing"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
)

func compressedMessage(t *testing.T, plaintext []byte, key []byte) *jwe.Message {
	t.Helper()

	encryption := jwa.A256GCM()

	protectedHeader := &header.Header{
		Algorithm:            jwa.Dir(),
		EncryptionAlgorithm:  encryption,
		CompressionAlgorithm: header.Deflate,
	}

	encodedProtectedHeader, err := protectedHeader.Marshal()
	if err != nil {
		t.Fatalf("cannot encode the header: %v", err)
	}

	var compressed bytes.Buffer

	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("cannot build the compressor: %v", err)
	}

	if _, err := writer.Write(plaintext); err != nil {
		t.Fatalf("cannot compress: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("cannot finish compressing: %v", err)
	}

	initializationVector := make([]byte, encryption.IVSize())

	ciphertext, tag, err := encryption.Encrypt(
		compressed.Bytes(), key, initializationVector, []byte(encodedProtectedHeader),
	)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	return &jwe.Message{
		ProtectedHeader:      protectedHeader,
		Recipients:           []*jwe.Recipient{{EncryptedKey: []byte{}}},
		InitializationVector: initializationVector,
		Ciphertext:           ciphertext,
		AuthenticationTag:    tag,
	}
}

func TestDecryptSurvivesADecompressionBomb(t *testing.T) {
	key := bytes.Repeat([]byte{7}, jwa.A256GCM().KeySize())

	bomb := make([]byte, (1<<24)+1)

	message := compressedMessage(t, bomb, key)

	if len(message.Ciphertext) > 1<<16 {
		t.Fatalf("the bomb did not compress: %d octets of ciphertext", len(message.Ciphertext))
	}

	if _, err := message.Decrypt(key); !errors.Is(err, jwe.ErrOversizedPlaintext) {
		t.Errorf("got %v, want ErrOversizedPlaintext", err)
	}
}
