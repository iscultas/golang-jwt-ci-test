package jws_test

import (
	"encoding/json/v2"
	"slices"
	"testing"

	"github.com/iscultas/jwt-go/jws"
)

func FuzzUnmarshalSignature(f *testing.F) {
	f.Add(`{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"one"},"signature":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"alg":"HS256"},"signature":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19","signature":"AAAA"}`)
	f.Add(`{"header":{"b64":false},"signature":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","signature":"AAAA"}`)
	f.Add(`{"header":{"enc":"A128GCM"},"signature":"AAAA"}`)
	f.Add(`{"signature":"AAAA"}`)
	f.Add(`{"protected":"","header":{},"signature":""}`)
	f.Add(`{"protected":"!!!","signature":"AAAA"}`)
	f.Add(`{"signature":"!!!"}`)
	f.Add("{}")
	f.Add("null")
	f.Add("[]")

	f.Fuzz(func(t *testing.T, document string) {
		signature := new(jws.Signature)
		if err := json.Unmarshal([]byte(document), signature); err != nil {
			return
		}

		unprotected, err := signature.Header.Members()
		if err != nil {
			return
		}

		protected, err := signature.ProtectedHeader.Members()
		if err != nil {
			return
		}

		for _, name := range unprotected {
			if slices.Contains(protected, name) {
				t.Errorf("%q was accepted with %q in both headers", document, name)
			}
		}

		_, _ = json.Marshal(signature)
	})
}
