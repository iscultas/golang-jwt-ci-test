package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"slices"
	"testing"
)

func TestThumbprintMembersComeInLexicographicSequence(t *testing.T) {
	ellipticCurveKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot make an EC key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot make an RSA key: %v", err)
	}

	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot make an Ed25519 key: %v", err)
	}

	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot make an X25519 key: %v", err)
	}

	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("cannot make an ML-DSA key: %v", err)
	}

	testCases := []struct {
		name     string
		material any
		names    []string
	}{
		{"EC public", &ellipticCurveKey.PublicKey, []string{"crv", "kty", "x", "y"}},
		{"EC private", ellipticCurveKey, []string{"crv", "kty", "x", "y"}},
		{"RSA public", &rsaKey.PublicKey, []string{"e", "kty", "n"}},
		{"RSA private", rsaKey, []string{"e", "kty", "n"}},
		{"Ed25519 public", ed25519PublicKey, []string{"crv", "kty", "x"}},
		{"Ed25519 private", ed25519PrivateKey, []string{"crv", "kty", "x"}},
		{"X25519 public", x25519Key.PublicKey(), []string{"crv", "kty", "x"}},
		{"X25519 private", x25519Key, []string{"crv", "kty", "x"}},
		{"AKP public", mldsaKey.PublicKey(), []string{"alg", "kty", "pub"}},
		{"AKP private", mldsaKey, []string{"alg", "kty", "pub"}},
		{"oct", []byte("a symmetric key of thirty-two by"), []string{"k", "kty"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			members, err := NewKey(testCase.material).thumbprintMembers()
			if err != nil {
				t.Fatalf("cannot make the members: %v", err)
			}

			names := make([]string, 0, len(members))
			for _, member := range members {
				names = append(names, member.name)
			}

			if !slices.Equal(names, testCase.names) {
				t.Errorf("got the members %q, want %q", names, testCase.names)
			}

			if !slices.IsSorted(names) {
				t.Errorf("the members %q are not in lexicographic sequence", names)
			}

			for _, member := range members {
				if member.value == "" {
					t.Errorf("the %q member has no value", member.name)
				}
			}
		})
	}
}

func TestCanonicalJSONEscapesAValueThatNeedsIt(t *testing.T) {
	members := []thumbprintMember{{"k", "a\"b\\c\nd"}, {"kty", "oct"}}

	canonical, err := canonicalJSON(make([]byte, 0, canonicalJSONSize(members)), members)
	if err != nil {
		t.Fatalf("cannot write the members: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatalf("the result is not JSON: %v: %s", err, canonical)
	}

	for _, member := range members {
		if decoded[member.name] != member.value {
			t.Errorf("the %q member came back as %q, want %q", member.name, decoded[member.name], member.value)
		}
	}
}

func TestCanonicalJSONWritesIntoTheSpaceItIsGiven(t *testing.T) {
	members := []thumbprintMember{{"crv", "P-256"}, {"kty", "EC"}}

	destination := make([]byte, 0, canonicalJSONSize(members))

	canonical, err := canonicalJSON(destination, members)
	if err != nil {
		t.Fatalf("cannot write the members: %v", err)
	}

	if cap(canonical) != cap(destination) {
		t.Errorf("the writer made a new array of %d bytes for %d bytes of space", cap(canonical), cap(destination))
	}

	if string(canonical) != `{"crv":"P-256","kty":"EC"}` {
		t.Errorf("got %s", canonical)
	}
}
