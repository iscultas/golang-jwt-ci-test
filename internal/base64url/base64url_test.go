package base64url_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/iscultas/jwt-go/internal/base64url"
)

func TestEncodeGivesTheEmptyStringForNoOctets(t *testing.T) {
	if got := base64url.Encode(nil); got != "" {
		t.Errorf("Encode gave %q, want the empty string", got)
	}
}

func TestEncodeJSONAgreesWithEncodeOfMarshal(t *testing.T) {
	for _, value := range []any{
		map[string]any{},
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]string{"one": strings.Repeat("value", 500)},
		[]any{1.0, "two", nil, true},
		"a string with a \" and a \\ in it",
		nil,
	} {
		document, err := json.Marshal(value, json.Deterministic(true))
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}

		want := base64url.Encode(document)

		got, err := base64url.EncodeJSON(value, json.Deterministic(true))
		if err != nil {
			t.Fatalf("EncodeJSON: %v", err)
		}

		if got != want {
			t.Errorf("EncodeJSON of %#v gave %q, want %q", value, got, want)
		}
	}
}

func TestEncodeJSONTakesASecondBuffer(t *testing.T) {
	value := map[string]any{"outer": "value", "inner": encodesWhileMarshalling{}}

	encoded, err := base64url.EncodeJSON(value, json.Deterministic(true))
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}

	decoded, err := base64url.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	read := map[string]any{}
	if err := json.Unmarshal(decoded, &read); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if read["outer"] != "value" {
		t.Errorf("the outer member is %#v, want %q", read["outer"], "value")
	}

	if read["inner"] != innerEncoded {
		t.Errorf("the inner member is %#v, want %q", read["inner"], innerEncoded)
	}
}

var (
	innerOctets  = bytes.Repeat([]byte("inner"), 40)
	innerEncoded = base64url.Encode(innerOctets)
)

type encodesWhileMarshalling struct{}

func (encodesWhileMarshalling) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64url.Encode(innerOctets))
}

func TestEncodeSurvivesConcurrentUse(t *testing.T) {
	const goroutines = 32

	var group sync.WaitGroup

	for worker := range goroutines {
		group.Go(func() {
			value := bytes.Repeat([]byte{byte(worker)}, worker*97+1)
			want := base64.RawURLEncoding.EncodeToString(value)

			for range 200 {
				if got := base64url.Encode(value); got != want {
					t.Errorf("worker %d: Encode gave %q, want %q", worker, got, want)

					return
				}

				document := map[string]string{"value": want}

				encoded, err := base64url.EncodeJSON(document, json.Deterministic(true))
				if err != nil {
					t.Errorf("worker %d: EncodeJSON: %v", worker, err)

					return
				}

				octets, err := json.Marshal(document, json.Deterministic(true))
				if err != nil {
					t.Errorf("worker %d: Marshal: %v", worker, err)

					return
				}

				if encoded != base64url.Encode(octets) {
					t.Errorf("worker %d: EncodeJSON and Encode do not agree", worker)

					return
				}
			}
		})
	}

	group.Wait()
}

const (
	canonical = "QUJD"

	oneOctet  = "QQ"
	padBitSet = "QR"

	urlSafeAlphabet  = "-_8"
	standardAlphabet = "+/8="
)

var lineBreakSpellings = map[string]string{
	"a leading line feed":       "\n" + canonical,
	"an interior line feed":     canonical[:2] + "\n" + canonical[2:],
	"a trailing line feed":      canonical + "\n",
	"an interior carriage code": canonical[:2] + "\r" + canonical[2:],
	"an interior CRLF":          canonical[:2] + "\r\n" + canonical[2:],
}

func TestDecodeRefusesALineBreak(t *testing.T) {
	if decoded, err := base64url.Decode(canonical); err != nil || string(decoded) != "ABC" {
		t.Fatalf("Decode(%q) gave %q, %v; want \"ABC\", nil", canonical, decoded, err)
	}

	for name, encoded := range lineBreakSpellings {
		t.Run(name, func(t *testing.T) {
			decoded, err := base64url.Decode(encoded)
			if err == nil {
				t.Fatalf("Decode(%q) gave %q, want an error", encoded, decoded)
			}

			if !errors.Is(err, base64url.ErrLineBreak) {
				t.Errorf("Decode(%q) gave %v, want ErrLineBreak", encoded, err)
			}
		})
	}
}

func TestDecodeStandardRefusesALineBreak(t *testing.T) {
	if decoded, err := base64url.DecodeStandard(canonical); err != nil || string(decoded) != "ABC" {
		t.Fatalf("DecodeStandard(%q) gave %q, %v; want \"ABC\", nil", canonical, decoded, err)
	}

	for name, encoded := range lineBreakSpellings {
		t.Run(name, func(t *testing.T) {
			decoded, err := base64url.DecodeStandard(encoded)
			if err == nil {
				t.Fatalf("DecodeStandard(%q) gave %q, want an error", encoded, decoded)
			}

			if !errors.Is(err, base64url.ErrLineBreak) {
				t.Errorf("DecodeStandard(%q) gave %v, want ErrLineBreak", encoded, err)
			}
		})
	}
}

func TestDecodeRefusesANonCanonicalSpelling(t *testing.T) {
	decoded, err := base64url.Decode(oneOctet)
	if err != nil || string(decoded) != "A" {
		t.Fatalf("Decode(%q) gave %q, %v; want \"A\", nil", oneOctet, decoded, err)
	}

	if decoded, err := base64url.Decode(padBitSet); err == nil {
		t.Errorf("Decode(%q) gave %q, want an error: one octet had two spellings", padBitSet, decoded)
	}
}

func TestDecodeStandardRefusesANonCanonicalSpelling(t *testing.T) {
	decoded, err := base64url.DecodeStandard(oneOctet + "==")
	if err != nil || string(decoded) != "A" {
		t.Fatalf("DecodeStandard(%q) gave %q, %v; want \"A\", nil", oneOctet+"==", decoded, err)
	}

	if decoded, err := base64url.DecodeStandard(padBitSet + "=="); err == nil {
		t.Errorf("DecodeStandard(%q) gave %q, want an error: one octet had two spellings", padBitSet+"==", decoded)
	}
}

func TestDecodeTakesTheURLSafeAlphabetWithNoPadding(t *testing.T) {
	decoded, err := base64url.Decode(urlSafeAlphabet)
	if err != nil || !bytes.Equal(decoded, []byte{0xFB, 0xFF}) {
		t.Errorf("Decode(%q) gave %x, %v; want fbff, nil", urlSafeAlphabet, decoded, err)
	}

	if decoded, err := base64url.Decode(standardAlphabet); err == nil {
		t.Errorf("Decode(%q) gave %x, want an error", standardAlphabet, decoded)
	}

	if decoded, err := base64url.Decode(oneOctet + "=="); err == nil {
		t.Errorf("Decode(%q) gave %q, want an error: base64url carries no padding", oneOctet+"==", decoded)
	}
}

func TestDecodeStandardTakesTheStandardAlphabetWithPadding(t *testing.T) {
	decoded, err := base64url.DecodeStandard(standardAlphabet)
	if err != nil || !bytes.Equal(decoded, []byte{0xFB, 0xFF}) {
		t.Errorf("DecodeStandard(%q) gave %x, %v; want fbff, nil", standardAlphabet, decoded, err)
	}

	if decoded, err := base64url.DecodeStandard(urlSafeAlphabet); err == nil {
		t.Errorf("DecodeStandard(%q) gave %x, want an error", urlSafeAlphabet, decoded)
	}

	if decoded, err := base64url.DecodeStandard(strings.TrimRight(standardAlphabet, "=")); err == nil {
		t.Errorf("DecodeStandard of an unpadded value gave %x, want an error", decoded)
	}
}

func TestEncodeWritesTheURLSafeAlphabetWithNoPadding(t *testing.T) {
	if encoded := base64url.Encode([]byte{0xFB, 0xFF}); encoded != urlSafeAlphabet {
		t.Errorf("Encode of fbff gave %q, want %q", encoded, urlSafeAlphabet)
	}

	for length := 1; length <= 100; length++ {
		octets := bytes.Repeat([]byte{0xFB, 0xFF, 0x00}, length)[:length]

		encoded := base64url.Encode(octets)

		if strings.ContainsAny(encoded, "=") {
			t.Errorf("Encode of %d octets gave %q, which carries padding", length, encoded)
		}

		if strings.ContainsAny(encoded, "\r\n+/") {
			t.Errorf("Encode of %d octets gave %q, which is outside the URL-safe alphabet", length, encoded)
		}

		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			t.Errorf("Encode of %d octets gave %q, which a strict decoder refuses: %v", length, encoded, err)

			continue
		}

		if !bytes.Equal(decoded, octets) {
			t.Errorf("Encode of %d octets round tripped to %x, want %x", length, decoded, octets)
		}
	}
}
