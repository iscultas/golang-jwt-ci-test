// Package header supplies the JOSE header of RFC 7515 and RFC 7516.
//
// A [Header] holds the Header Parameters of a JWS or a JWE. The jws and jwe
// packages use it, because the two objects use one header and most parameters
// have the same function in the two.
//
// The package encodes a Header as the base64url JSON of a JWS Protected Header
// or a JWE Protected Header. See [Header.Marshal] and [Header.Unmarshal].
// [Header.Members] gives the member names that a header writes. A caller uses
// them for the disjointness rules of the two serializations.
//
// The package rejects a "crit" value that names an extension which it does not
// supply, and it rejects a "b64" value of false. See
// [ErrUnsupportedCriticalParameter] and [ErrUnencodedPayload].
//
// # Duplicate parameter names
//
// The Header Parameter names of a JOSE header are unique. A parser can reject a
// header that names one parameter two times, or read only the last occurrence
// of the name. This package rejects and gives [jsontext.ErrDuplicateName].
//
// A header that names "alg" two times can make a verifier and the application
// behind it read different algorithms out of one token, and no reader of the
// header can tell which one the producer signed. A rejection removes the
// disagreement. The jwk package rejects a duplicate member name in a JWK and in
// a JWK Set for the same cause.
//
// A caller reads the same error from the two decoders. The UnmarshalJSON
// methods of this module keep the signature that encoding/json reads, and their
// bodies decode with encoding/json/v2.
package header

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/iscultas/jwt-go/internal/base64url"
	"github.com/iscultas/jwt-go/internal/jsonerr"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

// Header is a JOSE header.
//
// A field with the zero value is a parameter that the header does not give, and
// the encoder does not write it.
//
// The zero Header gives no parameter and encodes to an empty object. See
// [Header.IsZero].
type Header struct {
	Type                            string
	ContentType                     string
	Algorithm                       jwa.Algorithm
	JWKSetURL                       *url.URL
	JWK                             *jwk.Key
	KeyID                           string
	X509URL                         *url.URL
	X509CertificateChain            []string
	X509CertificateSHA1Thumbprint   string
	X509CertificateSHA256Thumbprint string
	Critical                        []string

	// EncryptionAlgorithm is "enc", the JWE content encryption algorithm. It has a
	// type and is not a string, for the same cause as Algorithm. A value that
	// names an algorithm which this module does not supply gets a rejection where
	// a reader reads it. It does not continue to a position with less data about
	// the error.
	EncryptionAlgorithm jwa.ContentEncrypter

	// CompressionAlgorithm is "zip". [Deflate] is the only registered value.
	//
	// This module decompresses a header that gives this parameter, but it never
	// writes the parameter. The jwe package gives the cause.
	CompressionAlgorithm string

	// EphemeralPublicKey is "epk". It is the ephemeral public key of the producer
	// for ECDH-ES. It holds a public key only, and this package rejects a private
	// key here. See [ErrPrivateEphemeralKey].
	EphemeralPublicKey *jwk.Key

	// AgreementPartyUInfo and AgreementPartyVInfo are "apu" and "apv". This
	// package holds them decoded.
	AgreementPartyUInfo []byte
	AgreementPartyVInfo []byte

	// InitializationVector and AuthenticationTag are "iv" and "tag". They belong
	// to the AES GCM key wrapping algorithms and give the properties of the CEK
	// wrap operation. They are not the IV and the tag of the content encryption,
	// which the serialization holds and the header does not.
	InitializationVector []byte
	AuthenticationTag    []byte

	// PBES2SaltInput and PBES2Count are "p2s" and "p2c".
	PBES2SaltInput []byte
	PBES2Count     int

	encodedHeader string

	// Base64URLEncodePayload is the "b64" parameter. It selects whether the
	// payload is base64url encoded or is its own octets. A nil value is an absent
	// parameter.
	//
	// This module does not supply an unencoded payload, and for a JWT it must not.
	// RFC 7797 section 7 gives the rule: "JSON Web Tokens [JWT] MUST NOT use
	// "b64" with a "false" value". This is the cause of the update that RFC 7797
	// makes to RFC 7519. Thus this package rejects a false value.
	//
	// The parameter is here so that a header round-trips and a caller can check it.
	// To remove it as an unknown member changes the meaning of the payload with no
	// indication.
	Base64URLEncodePayload *bool
}

// WithJWKSetURL sets the "jku" parameter of the header. It is the URL of a JWK
// Set.
//
// The header keeps a copy, thus a caller that changes its own URL after this
// option runs does not change the header. [Header.JWKSetURL] is an exported
// field and a caller can still write to it directly. The copy is here to make
// this option behave as [jwk.WithX509URL] does, and not to make the field
// private.
func WithJWKSetURL(url *url.URL) func(*Header) {
	return func(header *Header) { header.JWKSetURL = url.Clone() }
}

// WithJWK sets the "jwk" parameter of the header. It is the public key that
// verifies the signature.
func WithJWK(jwk *jwk.Key) func(*Header) {
	return func(header *Header) { header.JWK = jwk }
}

// WithKeyID sets the "kid" parameter of the header. It is a hint about which
// key the recipient must use.
func WithKeyID(id string) func(*Header) {
	return func(header *Header) { header.KeyID = id }
}

// WithX509URL sets the "x5u" parameter of the header. It is the URL of an X.509
// certificate chain. The header keeps a copy, as [WithJWKSetURL] does.
func WithX509URL(url *url.URL) func(*Header) {
	return func(header *Header) { header.X509URL = url.Clone() }
}

// WithX509CertificateChain sets the "x5c" parameter of the header. Each element
// is a base64 DER certificate, and the first certificate holds the key that
// made the signature.
func WithX509CertificateChain(chain ...string) func(*Header) {
	return func(header *Header) { header.X509CertificateChain = chain }
}

// WithX509CertificateSHA1Thumbprint sets the "x5t" parameter of the header. It
// is the base64url SHA-1 thumbprint of the first certificate.
func WithX509CertificateSHA1Thumbprint(thumbprint string) func(*Header) {
	return func(header *Header) { header.X509CertificateSHA1Thumbprint = thumbprint }
}

// WithX509CertificateSHA256Thumbprint sets the "x5t#S256" parameter of the
// header. It is the base64url SHA-256 thumbprint of the first certificate.
func WithX509CertificateSHA256Thumbprint(thumbprint string) func(*Header) {
	return func(header *Header) { header.X509CertificateSHA256Thumbprint = thumbprint }
}

type rawHeader struct {
	Type                            string   `json:"typ,omitempty"`
	ContentType                     string   `json:"cty,omitempty"`
	Algorithm                       string   `json:"alg,omitempty"`
	JWKSetURL                       string   `json:"jku,omitempty"`
	JWK                             *jwk.Key `json:"jwk,omitempty"`
	KeyID                           string   `json:"kid,omitempty"`
	X509URL                         string   `json:"x5u,omitempty"`
	X509CertificateChain            []string `json:"x5c,omitempty"`
	X509CertificateSHA1Thumbprint   string   `json:"x5t,omitempty"`
	X509CertificateSHA256Thumbprint string   `json:"x5t#S256,omitempty"`
	Critical                        []string `json:"crit,omitempty"`
	EncryptionAlgorithm             string   `json:"enc,omitempty"`
	CompressionAlgorithm            string   `json:"zip,omitempty"`

	EphemeralPublicKey *jwk.Key `json:"epk,omitempty"`

	// The octet-string parameters are held as strings rather than []byte because
	// encoding/json writes []byte as standard base64 with padding, where JOSE
	// requires base64url without it.
	AgreementPartyUInfo  string `json:"apu,omitempty"`
	AgreementPartyVInfo  string `json:"apv,omitempty"`
	InitializationVector string `json:"iv,omitempty"`
	AuthenticationTag    string `json:"tag,omitempty"`
	PBES2SaltInput       string `json:"p2s,omitempty"`

	// omitzero and not omitempty: encoding/json/v2 removes a member for a value
	// that writes an empty JSON value, and 0 is not one of them. omitempty would
	// put "p2c":0 in every header that does not use PBES2.
	PBES2Count int `json:"p2c,omitzero"`

	// A pointer so that absent and false stay distinguishable: "b64" has a default
	// of true, so a plain bool would read an absent parameter as false and invert
	// the default.
	Base64URLEncodePayload *bool `json:"b64,omitempty"`
}

// UnencodedPayload is the "b64" Header Parameter name. This name occurs in
// "crit" each time that a header uses the parameter.
const UnencodedPayload = "b64"

// ErrUnencodedPayload is the error for a header with a "b64" value of false. Such
// a header gives a payload that is not base64url encoded.
//
// RFC 7797 section 7 prevents this for the only type of object that this module
// writes: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use
// "b64" with a "false" value."
//
// The error occurs in the two directions. A header that this package does not
// write is not a header that it accepts.
var ErrUnencodedPayload = errors.New("header: unencoded payload")

// ErrCriticalParameterMismatch is the error for a "crit" list that does not agree
// with the parameters in the header.
//
// The error occurs in two conditions. In the first condition "crit" names "b64"
// but the header has no "b64" parameter, which RFC 7515 section 4.1.11 prevents:
// "MUST NOT be used with ... Header Parameter values that are not present". In
// the second condition the header has "b64" but "crit" does not name it.
// RFC 7797 section 6 makes that name necessary. An implementation with no "b64"
// "b64" behavior then rejects the JWS and does not read the payload
// incorrectly.
var ErrCriticalParameterMismatch = errors.New("header: crit does not match the parameters present")

// ErrDuplicateCriticalParameter is the error for a "crit" list that names one
// parameter two times.
//
// RFC 7515 section 4.1.11 gives the rule: "Producers MUST NOT include Header
// Parameter names defined by this specification or [JWA] for use with JWS,
// duplicate names, or names that do not occur as Header Parameter names within
// the JOSE Header in the "crit" list."
var ErrDuplicateCriticalParameter = errors.New("header: duplicate critical parameter")

func checkCritical(critical []string, base64URLEncodePayload *bool) error {
	unsupported := make([]string, 0, len(critical))
	for _, parameter := range critical {
		if parameter != UnencodedPayload {
			unsupported = append(unsupported, parameter)
		}
	}

	if len(unsupported) != 0 {
		return fmt.Errorf("%w: %s", ErrUnsupportedCriticalParameter, strings.Join(unsupported, ", "))
	}

	for index, parameter := range critical {
		if slices.Contains(critical[index+1:], parameter) {
			return fmt.Errorf("%w: %s", ErrDuplicateCriticalParameter, parameter)
		}
	}

	namedCritical := slices.Contains(critical, UnencodedPayload)

	if base64URLEncodePayload == nil {
		if namedCritical {
			return fmt.Errorf("%w: crit names %s but no such parameter is present", ErrCriticalParameterMismatch, UnencodedPayload)
		}

		return nil
	}

	if !*base64URLEncodePayload {
		return ErrUnencodedPayload
	}

	if !namedCritical {
		return fmt.Errorf("%w: %s is present but crit does not name it", ErrCriticalParameterMismatch, UnencodedPayload)
	}

	return nil
}

// ErrUnsupportedCriticalParameter is the error for a header that gives a
// critical parameter which this package does not supply. A recipient must
// reject such a header, and cannot ignore the parameter.
//
// "b64" is the one extension parameter that this package reads. It reads that
// parameter to reject the one value that it cannot obey. Each other "crit"
// member is unsupported.
//
// The error occurs in the two directions. To encode a header that this package
// rejects on input lets a caller write a token that no reader accepts. This
// module is one such reader.
var ErrUnsupportedCriticalParameter = errors.New("header: unsupported critical parameter")

type octetParameter struct {
	name    string
	encoded *string
	decoded *[]byte
}

func (header *Header) octetParameters(rawHeader *rawHeader) []octetParameter {
	return []octetParameter{
		{"apu", &rawHeader.AgreementPartyUInfo, &header.AgreementPartyUInfo},
		{"apv", &rawHeader.AgreementPartyVInfo, &header.AgreementPartyVInfo},
		{"iv", &rawHeader.InitializationVector, &header.InitializationVector},
		{"tag", &rawHeader.AuthenticationTag, &header.AuthenticationTag},
		{"p2s", &rawHeader.PBES2SaltInput, &header.PBES2SaltInput},
	}
}

func (header *Header) raw() (*rawHeader, error) {
	if err := checkCritical(header.Critical, header.Base64URLEncodePayload); err != nil {
		return nil, err
	}

	rawHeader := &rawHeader{
		Base64URLEncodePayload:          header.Base64URLEncodePayload,
		Type:                            header.Type,
		ContentType:                     header.ContentType,
		JWK:                             header.JWK,
		KeyID:                           header.KeyID,
		X509CertificateChain:            header.X509CertificateChain,
		X509CertificateSHA1Thumbprint:   header.X509CertificateSHA1Thumbprint,
		X509CertificateSHA256Thumbprint: header.X509CertificateSHA256Thumbprint,
		Critical:                        header.Critical,
		CompressionAlgorithm:            header.CompressionAlgorithm,
		EphemeralPublicKey:              header.EphemeralPublicKey,
		PBES2Count:                      header.PBES2Count,
	}

	for _, parameter := range header.octetParameters(rawHeader) {
		*parameter.encoded = encodeOctets(*parameter.decoded)
	}

	if header.Algorithm != nil {
		rawHeader.Algorithm = header.Algorithm.String()
	}

	if header.EncryptionAlgorithm != nil {
		rawHeader.EncryptionAlgorithm = header.EncryptionAlgorithm.String()
	}

	if header.JWKSetURL != nil {
		rawHeader.JWKSetURL = header.JWKSetURL.String()
	}

	if header.X509URL != nil {
		rawHeader.X509URL = header.X509URL.String()
	}

	return rawHeader, nil
}

// MarshalJSON encodes the header as the JSON object.
//
// MarshalJSON does not write a parameter with a zero value. It gives:
//
//   - [ErrUnsupportedCriticalParameter] for a "crit" value other than "b64"
//   - [ErrDuplicateCriticalParameter] for a name two times in "crit"
//   - [ErrCriticalParameterMismatch] for a "crit" list that does not agree
//     with the header
//   - [ErrUnencodedPayload] for a "b64" value of false
func (header *Header) MarshalJSON() ([]byte, error) {
	rawHeader, err := header.raw()
	if err != nil {
		return nil, err
	}

	return json.Marshal(rawHeader)
}

// UnmarshalJSON decodes the JSON object into the header.
//
// UnmarshalJSON gives [jwa.ErrUnsupportedAlgorithm] for an "alg" or "enc" value
// that this module does not supply, and [ErrPrivateEphemeralKey] for an "epk"
// value with private key material. It applies the same "crit" and "b64" rules as
// MarshalJSON.
//
// UnmarshalJSON rejects a header that names one parameter two times, and gives
// [jsontext.ErrDuplicateName]. See the package documentation.
func (header *Header) UnmarshalJSON(data []byte) error {
	rawHeader := new(rawHeader)

	if err := json.Unmarshal(data, rawHeader); err != nil {
		return jsonerr.KeepDuplicateName(err)
	}

	if err := checkCritical(rawHeader.Critical, rawHeader.Base64URLEncodePayload); err != nil {
		return err
	}

	header.Base64URLEncodePayload = rawHeader.Base64URLEncodePayload
	header.Critical = rawHeader.Critical

	if rawHeader.Algorithm != "" {
		algorithm, ok := jwa.ByName(rawHeader.Algorithm)
		if !ok {
			return jwa.UnsupportedAlgorithm(rawHeader.Algorithm)
		}

		header.Algorithm = algorithm
	}

	header.Type = rawHeader.Type
	header.ContentType = rawHeader.ContentType

	if rawHeader.JWKSetURL != "" {
		jwkSetURL, err := url.Parse(rawHeader.JWKSetURL)
		if err != nil {
			return err
		}

		header.JWKSetURL = jwkSetURL
	}

	header.JWK = rawHeader.JWK
	header.KeyID = rawHeader.KeyID

	if rawHeader.X509URL != "" {
		x509URL, err := url.Parse(rawHeader.X509URL)
		if err != nil {
			return err
		}

		header.X509URL = x509URL
	}

	header.X509CertificateChain = rawHeader.X509CertificateChain
	header.X509CertificateSHA1Thumbprint = rawHeader.X509CertificateSHA1Thumbprint
	header.X509CertificateSHA256Thumbprint = rawHeader.X509CertificateSHA256Thumbprint

	if rawHeader.EncryptionAlgorithm != "" {
		algorithm, ok := jwa.ByName(rawHeader.EncryptionAlgorithm)
		if !ok {
			return jwa.UnsupportedAlgorithm(rawHeader.EncryptionAlgorithm)
		}

		encryptionAlgorithm, ok := algorithm.(jwa.ContentEncrypter)
		if !ok {
			return fmt.Errorf("%w: %s cannot encrypt content", jwa.ErrUnsupportedAlgorithm, rawHeader.EncryptionAlgorithm)
		}

		header.EncryptionAlgorithm = encryptionAlgorithm
	}

	header.CompressionAlgorithm = rawHeader.CompressionAlgorithm

	if rawHeader.EphemeralPublicKey.IsPrivate() {
		return ErrPrivateEphemeralKey
	}

	header.EphemeralPublicKey = rawHeader.EphemeralPublicKey
	header.PBES2Count = rawHeader.PBES2Count

	for _, parameter := range header.octetParameters(rawHeader) {
		decoded, err := decodeOctets(*parameter.encoded)
		if err != nil {
			return fmt.Errorf("header: %s: %w", parameter.name, err)
		}

		*parameter.decoded = decoded
	}

	return nil
}

// Deflate is the only registered "zip" value.
const Deflate = "DEF"

// ErrPrivateEphemeralKey is the error for an "epk" Header Parameter with secret
// key material.
//
// RFC 7518 section 4.6.1.1 gives the rule. The ephemeral public key "MUST contain
// only public key parameters and SHOULD contain only the minimum JWK parameters
// necessary to represent the key". A key agreement with such a header is
// correct, because the algorithm reads the public half only. Thus this error
// is not about an incorrect derived key.
//
// The cause is different. A header that the specification calls malformed must
// not get the same result as a correct header. The private half changes the JWK
// thumbprint of the key. Thus implementations that do not agree about the removal
// of that half also do not agree about the identity of the key. It is also better
// to tell a sender who made an ephemeral private key public.
var ErrPrivateEphemeralKey = errors.New("header: epk carries private key material")

// KeyParameters returns the Header Parameters that a key management algorithm
// reads.
//
// The jwa package cannot name the [Header] type, because header uses jwa and not
// the opposite. Thus the two packages use [jwa.KeyParameters] together, and
// this method makes that value.
func (header *Header) KeyParameters() *jwa.KeyParameters {
	parameters := &jwa.KeyParameters{
		AgreementPartyUInfo:  header.AgreementPartyUInfo,
		AgreementPartyVInfo:  header.AgreementPartyVInfo,
		InitializationVector: header.InitializationVector,
		AuthenticationTag:    header.AuthenticationTag,
		PBES2SaltInput:       header.PBES2SaltInput,
		PBES2Count:           header.PBES2Count,
	}

	if header.EphemeralPublicKey != nil {
		parameters.EphemeralPublicKey = header.EphemeralPublicKey.Material()
	}

	return parameters
}

// SetKeyParameters writes the Header Parameters that a key management algorithm
// made. It is the opposite of [Header.KeyParameters].
//
// SetKeyParameters gives [ErrPrivateEphemeralKey] if the ephemeral key holds
// private material.
func (header *Header) SetKeyParameters(parameters *jwa.KeyParameters) error {
	header.AgreementPartyUInfo = parameters.AgreementPartyUInfo
	header.AgreementPartyVInfo = parameters.AgreementPartyVInfo
	header.InitializationVector = parameters.InitializationVector
	header.AuthenticationTag = parameters.AuthenticationTag
	header.PBES2SaltInput = parameters.PBES2SaltInput
	header.PBES2Count = parameters.PBES2Count

	if parameters.EphemeralPublicKey == nil {
		header.EphemeralPublicKey = nil

		return nil
	}

	ephemeralPublicKey := jwk.NewKey(parameters.EphemeralPublicKey)

	if ephemeralPublicKey.Type() == "" {
		return fmt.Errorf("%w: epk: %T", jwk.ErrUnsupportedKeyType, parameters.EphemeralPublicKey)
	}

	if ephemeralPublicKey = ephemeralPublicKey.Public(); ephemeralPublicKey == nil {
		return fmt.Errorf("%w: epk: %T has no public half", jwk.ErrUnsupportedKeyType, parameters.EphemeralPublicKey)
	}

	header.EphemeralPublicKey = ephemeralPublicKey

	return nil
}

func encodeOctets(octets []byte) string {
	if octets == nil {
		return ""
	}

	return base64url.Encode(octets)
}

func decodeOctets(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}

	return base64url.Decode(encoded)
}

// Unmarshal decodes a base64url encoded JOSE header into the header. It also
// keeps the encoded octets, thus [Header.Marshal] gives the same text again. See
// [Header.Encoded].
//
// Unmarshal rejects a header that names one parameter two times, as
// [Header.UnmarshalJSON] does. Such a header keeps no octets, thus the
// passthrough that [Header.Marshal] does cannot emit it again.
func (header *Header) Unmarshal(encodedHeader string) error {
	headerJSON, err := base64url.Decode(encodedHeader)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(headerJSON, header); err != nil {
		return err
	}

	header.encodedHeader = encodedHeader

	return nil
}

// Members returns the JSON member names that this header writes, in the sequence
// of their names. A nil header gives none.
//
// Members calculates the names from the encoding and not from the struct fields.
// Thus each caller stays correct as this package adds parameters. A new field
// with a JSON tag comes into this result with no other change, but a list that
// a person writes becomes incorrect.
//
// A caller uses this method for the disjointness rules of the two JOSE
// serializations. The rule covers the two headers of a JWS and the three
// headers of a JWE.
func (header *Header) Members() ([]string, error) {
	if header == nil {
		return nil, nil
	}

	encodedHeader, err := header.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return MembersIn(encodedHeader)
}

// ErrMalformedHeader is the error for a JOSE header that is not a JSON object.
// A JOSE header is always an object.
var ErrMalformedHeader = errors.New("header: malformed header")

const memberCapacity = 8

type memberNames []string

// UnmarshalJSONFrom reads the names. It gives [ErrMalformedHeader] for a value
// that is not a JSON object.
func (names *memberNames) UnmarshalJSONFrom(decoder *jsontext.Decoder) error {
	token, err := decoder.ReadToken()
	if err != nil {
		return err
	}

	if token.Kind() != '{' {
		return fmt.Errorf("%w: got %s, want a JSON object", ErrMalformedHeader, token.Kind())
	}

	for decoder.PeekKind() != '}' {
		name, err := decoder.ReadToken()
		if err != nil {
			return err
		}

		*names = append(*names, name.String())

		if err := decoder.SkipValue(); err != nil {
			return err
		}
	}

	_, err = decoder.ReadToken()

	return err
}

// MembersIn returns the member names of an encoded JOSE header, in the sequence
// of their names. Empty input gives none.
//
// It is for the one caller that holds a header which it could not decode. A JWE
// per-recipient header that names an algorithm which this module does not
// supply stays as octets and gets no rejection. Its names stay part of the
// disjointness check. To read them from the JSON is the only procedure that
// obeys that rule. This function is here, and not in jwe, to keep one
// implementation of the member names of a header.
func MembersIn(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	names := make(memberNames, 0, memberCapacity)
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, err
	}

	slices.Sort(names)

	return names, nil
}

// IsZero reports whether the header gives no parameter and thus encodes to the
// empty object.
//
// The encoding/json package reads this method for a field with the omitzero
// tag. The "header" member is absent when the JWS Unprotected Header is empty.
// Without this method, a pointer to an empty header that is not nil encodes to
// {}.
//
// IsZero calculates the result from the encoding and not from the fields, for the
// same cause as [Header.Members]: the result stays correct as this package adds
// parameters. The octets that a protected header came in as are not part of the
// result, because they are not a parameter of the header.
func (header *Header) IsZero() bool {
	encodedHeader, err := header.MarshalJSON()

	return err == nil && string(encodedHeader) == "{}"
}

// Encoded returns the octets that [Header.Unmarshal] kept, or the empty string
// for a header that did not come from a document.
//
// [Header.Marshal] gives these octets and not an encoding of the fields. A caller
// that must know which of the two a signature includes reads them here.
func (header *Header) Encoded() string { return header.encodedHeader }

// SetEncoded makes [Header.Marshal] give these octets and not an encoding of the
// fields. The empty string removes them, thus Marshal encodes the fields again.
//
// This is dangerous, and it is a method and not a field for that cause. The
// octets come before each field of the header. Thus a header with fields that do
// not agree with the octets encodes as the octets and not as the fields. Only
// two types of caller have a use for it: a test that must make a header and its
// encoding different, and a caller that reads a document with a different decoder
// and must keep the octets that a signature includes.
func (header *Header) SetEncoded(encodedHeader string) { header.encodedHeader = encodedHeader }

// Marshal returns the header as the base64url encoded JSON of a JWS Protected
// Header or a JWE Protected Header.
//
// Marshal gives the octets that [Header.Unmarshal] kept, when the header has
// them. Thus a header that came from a document keeps its text, and a signature
// on that text stays correct. Those octets come before each field of the header.
// See [Header.Encoded].
func (header *Header) Marshal() (string, error) {
	if header.encodedHeader != "" {
		return header.encodedHeader, nil
	}

	rawHeader, err := header.raw()
	if err != nil {
		return "", err
	}

	return base64url.EncodeJSON(rawHeader)
}

// String returns the base64url encoded JSON of the header. It panics where
// [Header.Marshal] gives an error. A caller with a header that it does not
// trust must use [Header.Marshal].
func (header *Header) String() string {
	encodedHeader, err := header.Marshal()
	if err != nil {
		panic(err)
	}

	return encodedHeader
}
