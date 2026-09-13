package header_test

import (
	"encoding/json/v2"
	"slices"
	"testing"

	"github.com/iscultas/jwt-go/header"
)

func FuzzUnmarshalHeader(f *testing.F) {
	f.Add(`{"alg":"HS256"}`)
	f.Add(`{"alg":"ES256","typ":"JWT","cty":"JWT","kid":"one"}`)
	f.Add(`{"alg":"HS256","b64":false,"crit":["b64"]}`)
	f.Add(`{"alg":"HS256","crit":["b64","b64"]}`)
	f.Add(`{"alg":"HS256","crit":[]}`)
	f.Add(`{"alg":"dir","enc":"A128GCM"}`)
	f.Add(`{"alg":"A128GCMKW","enc":"A128CBC-HS256","iv":"AAAAAAAAAAAAAAAA","tag":"AAAAAAAAAAAAAAAAAAAAAA"}`)
	f.Add(`{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAAAAAA","p2c":1000}`)
	f.Add(`{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"},"apu":"AAAA","apv":"AAAA"}`)
	f.Add(`{"alg":"dir","enc":"A128GCM","zip":"DEF"}`)
	f.Add(`{"alg":"HS256","jku":"https://example.com/keys.jwks"}`)
	f.Add(`{"alg":"HS256","x5u":"https://example.com/cert.pem","x5c":["AAAA"],"x5t":"AAAA","x5t#S256":"AAAA"}`)
	f.Add(`{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}}`)
	f.Add(`{"alg":"unheard of"}`)
	f.Add(`{"private":"parameter"}`)
	f.Add("{}")
	f.Add("null")
	f.Add("[]")
	f.Add("")

	f.Fuzz(func(t *testing.T, document string) {
		parsed := new(header.Header)
		if err := json.Unmarshal([]byte(document), parsed); err != nil {
			return
		}

		_ = parsed.KeyParameters()

		_, _ = parsed.Marshal()

		members, err := parsed.Members()
		if err != nil {
			return
		}

		if parsed.IsZero() != (len(members) == 0) {
			t.Errorf("IsZero is %v but the header declares %d members: %v", parsed.IsZero(), len(members), members)
		}

		if !slices.IsSorted(members) {
			t.Errorf("Members returned %v, which is not sorted", members)
		}

		if compacted := slices.Compact(slices.Clone(members)); len(compacted) != len(members) {
			t.Errorf("Members returned %v, which repeats a name", members)
		}

		encoded, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		named, err := header.MembersIn(encoded)
		if err != nil {
			t.Fatalf("cannot read the members of %s: %v", encoded, err)
		}

		if !slices.Equal(named, members) {
			t.Errorf("Members returned %v but MembersIn read %v from the same encoding", members, named)
		}

		reparsed := new(header.Header)
		if err := json.Unmarshal(encoded, reparsed); err != nil {
			t.Fatalf("a header this package wrote did not decode: %s: %v", encoded, err)
		}

		roundTripped, err := reparsed.Members()
		if err != nil {
			t.Fatalf("cannot read the members of a round-tripped header %s: %v", encoded, err)
		}

		if !slices.Equal(roundTripped, members) {
			t.Errorf("the members changed across a round trip: %v then %v", members, roundTripped)
		}
	})
}
