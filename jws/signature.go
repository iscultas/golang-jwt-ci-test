// Package jws supplies JSON Web Signature, RFC 7515.
//
// A [Signature] is one signature on a JWS, with the JWS Protected Header, the
// optional JWS Unprotected Header, and the signature octets. The jwt package uses
// this package to sign and verify a token.
//
// The two headers must hold no member name together. [Signature.Disjoint]
// applies that rule, and MarshalJSON and UnmarshalJSON also apply it.
//
// This package rejects a header with an "enc" member. Such a member makes the
// object a JWE and not a JWS. See [ErrEncryptionAlgorithm].
package jws

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/internal/base64url"
	"github.com/iscultas/jwt-go/internal/jsonerr"
)

// Signature is one signature on a JWS.
//
// ProtectedHeader is the JWS Protected Header, and the signature includes it.
// Header is the JWS Unprotected Header, and the signature does not include it.
// It is nil when the JWS has no such header. Signature holds the signature
// octets in their decoded representation.
//
// The two headers must hold no member name together. See
// [ErrDuplicateHeaderParameter].
type Signature struct {
	ProtectedHeader *header.Header
	Header          *header.Header
	Signature       []byte
}

// WithProtectedHeader applies the options to the JWS Protected Header of the
// signature. The signature includes each parameter that this option sets.
func WithProtectedHeader(options ...func(*header.Header)) func(*Signature) {
	return func(signature *Signature) {
		for _, option := range options {
			option(signature.ProtectedHeader)
		}
	}
}

// WithHeader makes a JWS Unprotected Header and applies the options to it. The
// signature does not include the parameters that this option sets.
//
// The protected header and the unprotected header must hold no member name
// together. See [ErrDuplicateHeaderParameter].
func WithHeader(options ...func(*header.Header)) func(*Signature) {
	return func(signature *Signature) {
		signature.Header = new(header.Header)

		for _, option := range options {
			option(signature.Header)
		}
	}
}

// Unmarshal reads the encoded protected header and the encoded signature of the
// JWS Compact Serialization. That serialization has no unprotected header, thus
// Unmarshal sets that field to nil.
//
// Unmarshal gives [ErrEncryptionAlgorithm] if the protected header holds an
// "enc" member.
func (signature *Signature) Unmarshal(encodedHeader, encodedSignature string) error {
	protectedHeader := new(header.Header)
	if err := protectedHeader.Unmarshal(encodedHeader); err != nil {
		return err
	}

	if err := checkContentEncryption(protectedHeader); err != nil {
		return err
	}

	decodedSignature, err := base64url.Decode(encodedSignature)
	if err != nil {
		return err
	}

	signature.ProtectedHeader = protectedHeader
	signature.Signature = decodedSignature

	return nil
}

// String returns the base64url encoding of the signature octets, as a JWS
// serialization holds them.
func (signature *Signature) String() string {
	return base64url.Encode(signature.Signature)
}

type rawSignature struct {
	ProtectedHeader string `json:"protected"`

	// Header uses omitzero and not omitempty. This member is absent when the JWS
	// Unprotected Header is empty, and omitempty removes a nil header only.
	// [WithHeader] with no options leaves an empty header that is not nil. Such a
	// header encodes to {}, which breaks the same rule.
	Header *header.Header `json:"header,omitzero"`

	Signature string `json:"signature"`
}

// MarshalJSON encodes the signature for the JWS General or Flattened
// Serialization.
//
// MarshalJSON applies the same rules as UnmarshalJSON. A serialization that this
// package rejects on input is not a serialization that it writes. It gives:
//
//   - [ErrDuplicateHeaderParameter] for a member name in the two headers
//   - [ErrUnprotectedUnencodedPayload] for a "b64" member in the unprotected
//     header
//   - [ErrEncryptionAlgorithm] for an "enc" member in one of the two headers
func (signature *Signature) MarshalJSON() ([]byte, error) {
	if err := disjoint(signature.ProtectedHeader, signature.Header); err != nil {
		return nil, err
	}

	if err := checkUnencodedPayload(signature.Header); err != nil {
		return nil, err
	}

	if err := checkContentEncryption(signature.ProtectedHeader, signature.Header); err != nil {
		return nil, err
	}

	encodedProtectedHeader, err := signature.ProtectedHeader.Marshal()
	if err != nil {
		return nil, err
	}

	return json.Marshal(
		&rawSignature{
			ProtectedHeader: encodedProtectedHeader,
			Header:          signature.Header,
			Signature:       signature.String(),
		},
	)
}

// ErrDuplicateHeaderParameter is the error for a protected header and an
// unprotected header of one signature that give the same parameter.
//
// Their member names are disjoint. A parameter that occurs again in the
// unprotected header gives a signed value again, but not in the coverage of the
// signature.
var ErrDuplicateHeaderParameter = errors.New("jws: duplicate header parameter")

// Disjoint reports whether the protected header and the unprotected header of
// this signature hold no Header Parameter name together. This is necessary.
// Disjoint gives [ErrDuplicateHeaderParameter] for a name in the two headers.
//
// MarshalJSON and UnmarshalJSON also apply this rule. But a caller that
// verifies a signature which it did not decode must use this method. A
// signature that a caller assembled in memory is one example.
func (signature *Signature) Disjoint() error {
	return disjoint(signature.ProtectedHeader, signature.Header)
}

// ErrUnprotectedUnencodedPayload is the error for a "b64" member in the JWS
// Unprotected Header.
//
// RFC 7797 section 3 puts that member in the protected header only: "When used,
// this Header Parameter MUST be integrity protected; therefore, it MUST occur
// only within the JWS Protected Header." A "b64" member that is not in the
// coverage of the signature can change in transit. To prevent that change is
// the function of integrity protection here.
var ErrUnprotectedUnencodedPayload = errors.New("jws: b64 in the unprotected header")

func checkUnencodedPayload(unprotectedHeader *header.Header) error {
	if unprotectedHeader != nil && unprotectedHeader.Base64URLEncodePayload != nil {
		return ErrUnprotectedUnencodedPayload
	}

	return nil
}

// ErrEncryptionAlgorithm is the error for a JWS header that holds an "enc"
// member.
//
// RFC 7516 section 9 gives three procedures to tell a JWS from a JWE, and it
// makes the three agree: the count of segments, the members of the JSON
// serialization, and the header. The text of the last one is: "If the 'enc'
// member is available, it is a JWE; otherwise, it is a JWS." An object with three
// segments and an "enc" member gets a different result from each procedure. The section knows this condition, and records that the procedures
// "may yield different results for malformed inputs".
//
// To reject such an object is the only safe result. To accept it lets a producer
// select which rule a given recipient applies. One relying party then verifies a
// signature on content that a different party decrypts. That is the algorithm
// confusion of RFC 8725 section 3.1, by a different path.
var ErrEncryptionAlgorithm = errors.New("jws: enc in a JWS header")

func checkContentEncryption(headers ...*header.Header) error {
	for _, candidate := range headers {
		if candidate != nil && candidate.EncryptionAlgorithm != nil {
			return fmt.Errorf("%w: %s", ErrEncryptionAlgorithm, candidate.EncryptionAlgorithm)
		}
	}

	return nil
}

func disjoint(protectedHeader, unprotectedHeader *header.Header) error {
	unprotectedMembers, err := unprotectedHeader.Members()
	if err != nil {
		return err
	}
	if len(unprotectedMembers) == 0 {
		return nil
	}

	protectedMembers, err := protectedHeader.Members()
	if err != nil {
		return err
	}

	duplicates := make([]string, 0, len(unprotectedMembers))
	for _, name := range unprotectedMembers {
		if slices.Contains(protectedMembers, name) {
			duplicates = append(duplicates, name)
		}
	}

	if len(duplicates) != 0 {
		return fmt.Errorf("%w: %s", ErrDuplicateHeaderParameter, strings.Join(duplicates, ", "))
	}

	return nil
}

// UnmarshalJSON decodes one signature of the JWS General or Flattened
// Serialization.
//
// UnmarshalJSON gives:
//
//   - [ErrUnprotectedUnencodedPayload] for a "b64" member in the unprotected
//     header
//   - [ErrEncryptionAlgorithm] for an "enc" member in one of the two headers
//   - [ErrDuplicateHeaderParameter] for a member name in the two headers
//   - [encoding/json/jsontext.ErrDuplicateName] for a member name two times in
//     one of the objects
func (signature *Signature) UnmarshalJSON(data []byte) error {
	var rawSignature rawSignature

	if err := json.Unmarshal(data, &rawSignature); err != nil {
		return jsonerr.KeepDuplicateName(err)
	}

	protectedHeader := new(header.Header)
	if err := protectedHeader.Unmarshal(rawSignature.ProtectedHeader); err != nil {
		return err
	}

	if err := checkUnencodedPayload(rawSignature.Header); err != nil {
		return err
	}

	if err := checkContentEncryption(protectedHeader, rawSignature.Header); err != nil {
		return err
	}

	if err := disjoint(protectedHeader, rawSignature.Header); err != nil {
		return err
	}

	decodedSignature, err := base64url.Decode(rawSignature.Signature)
	if err != nil {
		return err
	}

	signature.ProtectedHeader = protectedHeader
	signature.Header = rawSignature.Header
	signature.Signature = decodedSignature

	return nil
}
