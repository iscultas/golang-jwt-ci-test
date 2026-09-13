// Package base64url supplies the one base64 encoder and decoder for this module.
//
// The encoding of RFC 7515 section 2 accepts less than the encoding of the
// encoding/base64 package. There are two differences. A caller cannot know them.
// Thus this package applies them for all callers.
//
// The Go decoder ignores CR and LF at all positions. The Go documentation gives
// this text about [base64.Encoding.Strict]: "the input is still malleable, as new
// line characters (CR and LF) are still ignored". RFC 4648 section 3.3 gives the
// opposite instruction. A decoder MUST reject data that contains characters that
// are not in the alphabet, "unless the specification referring to this document
// explicitly states otherwise". RFC 7515 section 2 does the opposite. It gives
// base64url as an encoding "without the inclusion of any line breaks, whitespace,
// or other additional characters".
//
// The default Go decoder also accepts a last character with non-zero bits after
// the encoded octets. Thus more than one text value decodes to the same octets.
// RFC 4648 section 3.5 lets the decoder reject such a value: "decoders MAY chose
// to reject an encoding if the pad bits have not been set to zero". Section 12
// gives the cause. Such values "may be abused to leak information or used to
// bypass string equality comparisons".
//
// The two differences were important in this module. Before this package, a JWK
// could hold the same key with two different "x" values. A JWK Thumbprint URI
// could also name a key with a text value that ThumbprintURI does not make. That
// URI is the only key identifier this module gives for a string compare.
package base64url

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync"
)

// ErrLineBreak is the error for a value that contains CR or LF.
//
// These two characters have a different error because encoding/base64 does not
// catch them. That package rejects all other characters that are not in the
// alphabet. Thus a check for CR and LF closes RFC 4648 section 3.3, and no more
// checks are necessary.
var ErrLineBreak = errors.New("base64url: value contains a line break")

func checkAlphabet(encoded string) error {
	if strings.ContainsAny(encoded, "\r\n") {
		return ErrLineBreak
	}

	return nil
}

const maxPooledBuffer = 1 << 16

var buffers = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// GetBuffer returns an empty buffer from the pool. The caller gives it back with
// [PutBuffer].
//
// The two functions are exported because one pool serves the module. A second
// pool in a second package makes two sets of buffers for one program. The jwk
// package builds the canonical JSON of a thumbprint, which is octets that go
// into a hash and then go away, thus that package makes the same use of a
// buffer as the two encoders here.
func GetBuffer() *bytes.Buffer { return buffers.Get().(*bytes.Buffer) } //nolint:forcetypeassert // The New of this pool makes a *bytes.Buffer, and nothing else puts into it.

// PutBuffer gives a buffer back to the pool. The caller must hold no slice of
// that buffer after this call. Each caller here makes its string first.
//
// PutBuffer drops a buffer that is above [maxPooledBuffer]. See that constant.
func PutBuffer(buffer *bytes.Buffer) {
	if buffer.Cap() > maxPooledBuffer {
		return
	}

	buffer.Reset()
	buffers.Put(buffer)
}

// Encode writes octets in the base64url encoding. This encoding uses the
// URL-safe and filename-safe alphabet, with no padding.
//
// The Go encoder was always canonical. Thus Encode does not change the data that
// the module sends. Encode is here to keep the two directions of the encoding
// together. A reader who looks for the rule finds it near the values it controls.
//
// Encode does not call base64.Encoding.EncodeToString. That method makes a
// buffer for the text and then copies the buffer into the string that it gives
// back. Encode writes into a buffer from the pool. Thus the string is the one
// allocation.
func Encode(octets []byte) string {
	if len(octets) == 0 {
		return ""
	}

	buffer := GetBuffer()
	defer PutBuffer(buffer)

	buffer.Grow(base64.RawURLEncoding.EncodedLen(len(octets)))

	return string(base64.RawURLEncoding.AppendEncode(buffer.AvailableBuffer(), octets))
}

// EncodeJSON returns the base64url of the JSON encoding of value. The options go
// to the JSON encoder.
//
// EncodeJSON gives the same text as [Encode] of the result of json.Marshal, and
// it makes one allocation in place of three. json.Marshal copies the buffer of
// its encoder before it gives the octets back, because that encoder goes to a
// pool. json.MarshalWrite writes into a buffer that this function owns, and it
// copies nothing.
//
// A caller with a type that has a MarshalJSON method must give the value that
// the method encodes, and not the value with the method. The JSON encoder calls
// such a method and makes a slice of its result. That slice is one of the
// allocations that this function removes.
func EncodeJSON(value any, options ...json.Options) (string, error) {
	buffer := GetBuffer()
	defer PutBuffer(buffer)

	if err := json.MarshalWrite(buffer, value, options...); err != nil {
		return "", err
	}

	buffer.Grow(base64.RawURLEncoding.EncodedLen(buffer.Len()))

	return string(base64.RawURLEncoding.AppendEncode(buffer.AvailableBuffer(), buffer.Bytes())), nil
}

// Decode reads one base64url value. It is accurate, and it rejects line breaks.
//
// A producer that follows RFC 7515 cannot write a value that Decode rejects.
// Thus Decode removes no data that a reader could use. Decode also makes sure
// that a given octet string has only one text value. This property lets a caller
// compare an encoded value as a string.
func Decode(encoded string) ([]byte, error) {
	if err := checkAlphabet(encoded); err != nil {
		return nil, err
	}

	return base64.RawURLEncoding.Strict().DecodeString(encoded)
}

// DecodeStandard reads the padded base64 with the standard alphabet. RFC 7517
// section 4.7 gives this encoding for "x5c", which is "base64-encoded (Section 4
// of [RFC4648] -- not base64url-encoded) DER".
//
// The same two rules apply. The rule about line breaks is important here. A PEM
// file breaks a certificate at 64 columns, and before this change such a
// certificate parsed. RFC 7517 gives no license for this. Section 4.7 points to
// RFC 4648 section 4, and that encoding contains no line breaks. Thus the module
// read a document that no producer writes.
func DecodeStandard(encoded string) ([]byte, error) {
	if err := checkAlphabet(encoded); err != nil {
		return nil, err
	}

	return base64.StdEncoding.Strict().DecodeString(encoded)
}
