package rfc7516_test

import (
	"bytes"
	"compress/flate"
	"testing"
)

func deflate(t *testing.T, plaintext []byte) []byte {
	t.Helper()

	var compressed bytes.Buffer

	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("cannot build a writer: %v", err)
	}

	if _, err := writer.Write(plaintext); err != nil {
		t.Fatalf("cannot compress: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("cannot flush: %v", err)
	}

	return compressed.Bytes()
}
