package jwe_test

import (
	"bytes"
	"encoding/json/v2"
	"testing"

	"github.com/iscultas/jwt-go/jwe"
)

func FuzzUnmarshal(f *testing.F) {
	f.Add("")
	f.Add("a.b.c.d.e")
	f.Add("not.a.jwe")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0....")
	f.Add(`{"ciphertext":""}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","ciphertext":"","recipients":[null]}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","ciphertext":"","encrypted_key":"","recipients":[{}]}`)

	key := bytes.Repeat([]byte{7}, 32)

	f.Fuzz(func(t *testing.T, encoded string) {
		if message, err := jwe.Unmarshal(encoded); err == nil {
			_, _ = message.Decrypt(key)
			_, _ = message.Marshal()
			_, _ = json.Marshal(message)
		}

		decoded := new(jwe.Message)
		if err := json.Unmarshal([]byte(encoded), decoded); err == nil {
			_, _ = decoded.Decrypt(key)
			_, _ = json.Marshal(decoded)
		}
	})
}
