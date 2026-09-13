// Package jwt supplies JSON Web Token, RFC 7519.
//
// A [Token] holds the claims and the signatures on them. [NewToken] makes one
// with options for example [WithIssuer] and [WithSignature]. [Token.Marshal]
// gives the compact serialization, and [Unmarshal] reads one. [Token.Verify]
// checks the signatures and the claims together.
//
// A JWT is a JWS or a JWE, and this package writes a JWS by default.
// [WithEncryption] makes a JWE JWT, and [Token.Decrypt] reads one.
//
// The package also supplies parts of other specifications:
//
//   - RFC 7800, the "cnf" confirmation claim. See [WithConfirmation].
//   - RFC 8725, the best current practice for JWT security. See
//     [DefaultVerificationConfig].
//   - RFC 9068, the JWT profile for OAuth 2.0 access tokens.
//
// A caller adds the rules of a profile with [WithRule] and [WithIssuanceRule].
// This package gives no rule.
package jwt

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/internal/base64url"
	"github.com/iscultas/jwt-go/internal/jsonerr"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

var (
	// ErrMalformedToken is the error for a token with incorrect structure.
	ErrMalformedToken = errors.New("jwt: malformed token")

	// ErrMalformedClaim is the error for a claim that is present but does not
	// have the type that its registered name gives it.
	ErrMalformedClaim = errors.New("jwt: malformed claim")

	// ErrUnsigned is the error for a token with no signature. Such a token gives
	// no data about its producer, thus this package rejects it and does not
	// report it as verified.
	ErrUnsigned = errors.New("jwt: token carries no signature")

	// ErrMultipleSignatures is the error for a token with more than one signature
	// in the compact serialization. That serialization holds one signature only.
	ErrMultipleSignatures = errors.New("jwt: compact serialization cannot carry multiple signatures")

	// ErrExpired is the error for an "exp" claim in the past.
	ErrExpired = errors.New("jwt: token expired")

	// ErrNotYetValid is the error for an "nbf" claim in the future.
	ErrNotYetValid = errors.New("jwt: token not valid yet")

	// ErrForbiddenAlgorithm is the error for a signature with an algorithm that
	// the [VerificationConfig] does not permit.
	ErrForbiddenAlgorithm = errors.New("jwt: forbidden algorithm")

	// ErrUnverified is the error for a signature that does not verify.
	ErrUnverified = errors.New("jwt: unverified signature")

	// ErrUnexpectedIssuer is the error for an "iss" claim that is not equal to the
	// value in the [VerificationConfig].
	ErrUnexpectedIssuer = errors.New("jwt: unexpected issuer")

	// ErrUnexpectedAudience is the error for an "aud" claim that does not hold
	// the value in the [VerificationConfig].
	ErrUnexpectedAudience = errors.New("jwt: unexpected audience")

	// ErrUnexpectedSubject is the error for a "sub" claim that is not equal to
	// the value in the [VerificationConfig].
	ErrUnexpectedSubject = errors.New("jwt: unexpected subject")

	// ErrUnexpectedType is the error for a "typ" header parameter that is not
	// equal to the value in the [VerificationConfig]. The default value is "JWT".
	ErrUnexpectedType = errors.New("jwt: unexpected token type")

	// ErrTooOld is the error for an "iat" claim that gives an age greater than
	// the age that [WithMaxAge] permits.
	ErrTooOld = errors.New("jwt: token too old")

	// ErrIssuedInFuture is the error for an "iat" claim after the current time.
	ErrIssuedInFuture = errors.New("jwt: token issued in the future")

	// ErrReplayedToken is the error for a "jti" claim that the [IDStore] of the
	// recipient saw before.
	ErrReplayedToken = errors.New("jwt: token already used")
)

func malformedClaim(name string, value any) error {
	return fmt.Errorf("%w: %s: got %T", ErrMalformedClaim, name, value)
}

type numericDate struct {
	time    time.Time
	present bool
}

func newNumericDate(value *time.Time) numericDate {
	if value == nil {
		return numericDate{}
	}

	return numericDate{time: *value, present: true}
}

func (date *numericDate) pointer() *time.Time {
	if !date.present {
		return nil
	}

	return &date.time
}

// MarshalJSONTo writes the seconds.
func (date numericDate) MarshalJSONTo(encoder *jsontext.Encoder) error {
	return encoder.WriteToken(jsontext.Int(date.time.Unix()))
}

// UnmarshalJSONFrom reads a NumericDate. It gives [ErrMalformedClaim] for a value
// that is not a JSON number.
//
// A NumericDate can be a value that is not an integer, thus this method reads a
// float and then removes the fraction. The map decoder that this type replaced
// did the same, because it read each JSON number as a float64.
func (date *numericDate) UnmarshalJSONFrom(decoder *jsontext.Decoder) error {
	token, err := decoder.ReadToken()
	if err != nil {
		return err
	}

	if token.Kind() != '0' {
		return malformedKind(token.Kind())
	}

	seconds, err := token.Float()
	if err != nil {
		return err
	}

	date.time = time.Unix(int64(seconds), 0)
	date.present = true

	return nil
}

type audience []string

// MarshalJSONTo writes one string for a single audience, and an array for more
// than one. The first form is permitted, and it is the form nearly every issuer
// emits.
func (audience audience) MarshalJSONTo(encoder *jsontext.Encoder) error {
	if len(audience) == 1 {
		return encoder.WriteToken(jsontext.String(audience[0]))
	}

	if err := encoder.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}

	for _, member := range audience {
		if err := encoder.WriteToken(jsontext.String(member)); err != nil {
			return err
		}
	}

	return encoder.WriteToken(jsontext.EndArray)
}

// UnmarshalJSONFrom reads the two forms of the claim. It gives
// [ErrMalformedClaim] for a value that is not a string, and for an array with a
// member that is not a string.
func (audience *audience) UnmarshalJSONFrom(decoder *jsontext.Decoder) error {
	if decoder.PeekKind() != '[' {
		token, err := decoder.ReadToken()
		if err != nil {
			return err
		}

		if token.Kind() != '"' {
			return malformedKind(token.Kind())
		}

		*audience = append((*audience)[:0], token.String())

		return nil
	}

	if _, err := decoder.ReadToken(); err != nil {
		return err
	}

	members := (*audience)[:0]

	for decoder.PeekKind() != ']' {
		token, err := decoder.ReadToken()
		if err != nil {
			return err
		}

		if token.Kind() != '"' {
			return malformedKind(token.Kind())
		}

		members = append(members, token.String())
	}

	if _, err := decoder.ReadToken(); err != nil {
		return err
	}

	*audience = members

	return nil
}

type claims struct {
	Audience       audience    `json:"aud,omitzero"`
	ExpirationTime numericDate `json:"exp,omitzero"`
	IssuedAt       numericDate `json:"iat,omitzero"`
	Issuer         string      `json:"iss,omitzero"`
	ID             string      `json:"jti,omitzero"`
	NotBefore      numericDate `json:"nbf,omitzero"`
	Subject        string      `json:"sub,omitzero"`

	// PrivateClaims holds each claim that is not one of the seven above. It is
	// last, because encoding/json/v2 writes an embedded fallback after every
	// declared field.
	//
	// [WithPrivateClaim] rejects a registered name, and the decoder puts such a
	// name in the field that owns it, thus this map holds no registered name.
	// Where one arrives by a different path, the encoder rejects it as a
	// duplicate member if the field also holds a value, and writes it if the
	// field is empty. The map that this type replaced did the same.
	//
	// The map is nil until the first private claim, and [payload.setPrivateClaim]
	// makes it. A nil map reads as an empty one, thus each accessor gives the
	// same answer, and a token with registered claims only allocates no map.
	PrivateClaims map[string]any `json:",embed"`
}

type payload struct {
	claims

	encodedPayload string
}

var registeredClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

func (payload *payload) setPrivateClaim(name string, value any) {
	if payload.PrivateClaims == nil {
		payload.PrivateClaims = make(map[string]any, 1)
	}

	payload.PrivateClaims[name] = value
}

func goType(kind jsontext.Kind) string {
	switch kind {
	case 'n':
		return "<nil>"
	case 'f', 't':
		return "bool"
	case '"':
		return "string"
	case '0':
		return "float64"
	case '{':
		return "map[string]interface {}"
	case '[':
		return "[]interface {}"
	}

	return kind.String()
}

type malformedValue struct{ kind jsontext.Kind }

// Error returns the message of the error.
func (value malformedValue) Error() string {
	return fmt.Sprintf("%s: got %s", ErrMalformedClaim, goType(value.kind))
}

// Unwrap returns [ErrMalformedClaim], thus errors.Is finds it in a value that a
// decoder of this file gave and that this package did not name.
func (value malformedValue) Unwrap() error { return ErrMalformedClaim }

func malformedKind(kind jsontext.Kind) error {
	return malformedValue{kind}
}

func claimError(err error) error {
	if err == nil {
		return nil
	}

	if semantic, ok := errors.AsType[*json.SemanticError](err); ok {
		kind := semantic.JSONKind

		if value, ok := errors.AsType[malformedValue](err); ok {
			kind = value.kind
		}

		if name := semantic.JSONPointer.LastToken(); kind != 0 && slices.Contains(registeredClaims, name) {
			return fmt.Errorf("%w: %s: got %s", ErrMalformedClaim, name, goType(kind))
		}
	}

	if errors.Is(err, ErrMalformedClaim) {
		return err
	}

	return jsonerr.KeepDuplicateName(err)
}

// Marshal returns the base64url encoded JSON of the claims. It gives the octets
// that came in again when the payload holds them, thus a signature on those
// octets stays correct.
func (payload *payload) Marshal() (string, error) {
	if payload.encodedPayload == "" {
		encodedPayload, err := base64url.EncodeJSON(&payload.claims, json.Deterministic(true))
		if err != nil {
			return "", err
		}

		payload.encodedPayload = encodedPayload
	}

	return payload.encodedPayload, nil
}

func claim[T any](claims map[string]any, name string) (T, bool, error) {
	var zero T

	rawClaim, present := claims[name]
	if !present {
		return zero, false, nil
	}

	value, ok := rawClaim.(T)
	if !ok {
		return zero, true, malformedClaim(name, rawClaim)
	}

	return value, true, nil
}

func stringClaim(claims map[string]any, name string) (string, error) {
	value, _, err := claim[string](claims, name)

	return value, err
}

// UnmarshalJSON decodes the JSON object into the payload. It puts each name
// that is not a registered claim into the private claims.
//
// UnmarshalJSON rejects a claims set that names one claim two times, and gives
// [jsontext.ErrDuplicateName]. A parser can reject such a document or read the
// last occurrence. This package rejects: a token whose "iss" or "aud" reads
// differently to a verifier and to the application behind it is the failure
// that the rule prevents.
func (payload *payload) UnmarshalJSON(data []byte) error {
	return claimError(json.Unmarshal(data, &payload.claims))
}

// Unmarshal decodes a base64url encoded payload. It also keeps the encoded
// octets, thus [payload.Marshal] gives the same text again.
func (payload *payload) Unmarshal(encodedPayload string) error {
	payloadJSON, err := base64url.Decode(encodedPayload)
	if err != nil {
		return err
	}

	if err := payload.UnmarshalJSON(payloadJSON); err != nil {
		return err
	}

	payload.encodedPayload = encodedPayload

	return nil
}

func signingInput(encodedProtectedHeader, encodedPayload string) []byte {
	input := make([]byte, 0, len(encodedProtectedHeader)+len(".")+len(encodedPayload))
	input = append(input, encodedProtectedHeader...)
	input = append(input, '.')

	return append(input, encodedPayload...)
}

type pendingSignature struct {
	algorithm jwa.Signer
	key       *jwk.Key
	options   []func(*jws.Signature)
}

// Token is a JSON Web Token.
//
// A Token holds claims and the signatures on them. [NewToken] makes one, and the
// With options set its claims. The accessor methods, for example [Token.Issuer], give
// the claims back.
//
// This package does not make a signature until a caller marshals or verifies the
// token. Thus a caller can give the options in any sequence. See
// [WithSignature].
//
// A Token is safe for use by one goroutine at a time.
type Token struct {
	payload    *payload
	signatures []*jws.Signature
	pending    []pendingSignature

	tokenType string

	issuanceChecks []IssuanceRule

	pendingEncryption *encrypting
	message           *jwe.Message

	authenticatedTypes []string

	verified bool
}

// NewToken returns a [Token] with the options applied to it. It gives the error
// of the first option that is not correct.
func NewToken(options ...func(*Token) error) (*Token, error) {
	token := &Token{payload: new(payload)}

	for _, option := range options {
		if err := option(token); err != nil {
			return nil, err
		}
	}

	return token, nil
}

// WithIssuer sets the "iss" claim.
func WithIssuer(issuer string) func(*Token) error {
	return func(token *Token) error {
		token.payload.Issuer = issuer

		return nil
	}
}

// Issuer returns the "iss" claim.
func (token *Token) Issuer() string { return token.payload.Issuer }

// WithSubject sets the "sub" claim.
func WithSubject(subject string) func(*Token) error {
	return func(token *Token) error {
		token.payload.Subject = subject

		return nil
	}
}

// Subject returns the "sub" claim.
func (token *Token) Subject() string { return token.payload.Subject }

// WithAudience sets the "aud" claim.
func WithAudience(audience ...string) func(*Token) error {
	return func(token *Token) error {
		token.payload.Audience = audience

		return nil
	}
}

// Audience returns the "aud" claim.
func (token *Token) Audience() []string { return token.payload.Audience }

// WithExpirationTime sets the "exp" claim. A token with this claim before the
// current time gives [ErrExpired] on verification.
func WithExpirationTime(expirationTime *time.Time) func(*Token) error {
	return func(token *Token) error {
		token.payload.ExpirationTime = newNumericDate(expirationTime)

		return nil
	}
}

// ExpirationTime returns the "exp" claim. It gives nil when the token has no
// such claim.
func (token *Token) ExpirationTime() *time.Time { return token.payload.ExpirationTime.pointer() }

// WithNotBefore sets the "nbf" claim. A token with this claim in the future
// gives [ErrNotYetValid] on verification.
func WithNotBefore(notBefore *time.Time) func(*Token) error {
	return func(token *Token) error {
		token.payload.NotBefore = newNumericDate(notBefore)

		return nil
	}
}

// NotBefore returns the "nbf" claim. It gives nil when the token has no such
// claim.
func (token *Token) NotBefore() *time.Time { return token.payload.NotBefore.pointer() }

// WithIssuedAt sets the "iat" claim.
func WithIssuedAt(issuedAt *time.Time) func(*Token) error {
	return func(token *Token) error {
		token.payload.IssuedAt = newNumericDate(issuedAt)

		return nil
	}
}

// IssuedAt returns the "iat" claim. It gives nil when the token has no such
// claim.
func (token *Token) IssuedAt() *time.Time { return token.payload.IssuedAt.pointer() }

// WithID sets the "jti" claim.
func WithID(id string) func(*Token) error {
	return func(token *Token) error {
		token.payload.ID = id

		return nil
	}
}

// ID returns the "jti" claim.
func (token *Token) ID() string { return token.payload.ID }

// ErrReservedClaim is the error for a private claim with a registered name.
var ErrReservedClaim = errors.New("jwt: private claim may not use a registered name")

// WithPrivateClaim sets a claim that is not in the registered set.
//
// The name must not be "iss", "sub", "aud", "exp", "nbf", "iat" or "jti". Use
// the option of that claim. WithPrivateClaim gives [ErrReservedClaim] for one of
// those names.
func WithPrivateClaim(key string, value any) func(*Token) error {
	return func(token *Token) error {
		if slices.Contains(registeredClaims, key) {
			return fmt.Errorf("%w: %s", ErrReservedClaim, key)
		}

		token.payload.setPrivateClaim(key, value)

		return nil
	}
}

// PrivateClaim returns the value of the private claim with the given name. It
// gives nil when the token has no such claim.
//
// The result has the Go type that the decoder gives a JSON value of that shape:
// string, float64, bool, []any, map[string]any or nil. See [Token.Claim] for the
// same read with the type in the call.
func (token *Token) PrivateClaim(key string) any {
	return token.payload.PrivateClaims[key]
}

// Claim returns the value of the private claim with the given name as the type
// that T gives. The second result tells if the claim is present, and a claim
// that is not present is not an error: each claim is optional.
//
// T must be the Go type of the JSON value, as [Token.PrivateClaim] gives it:
// string for a JSON string, float64 for a JSON number, bool for true or false,
// []any for an array and map[string]any for an object. Claim gives
// [ErrMalformedClaim] for a claim of a different type, thus a caller reads the
// error and does not get a panic from an assertion.
//
// A method can declare a type parameter from Go 1.27. The registered claims read
// through the same procedure, which is why the accessors of this package can
// give one error for a claim of the wrong type.
func (token *Token) Claim[T any](name string) (T, bool, error) {
	return claim[T](token.payload.PrivateClaims, name)
}

// WithSignature records that this package must sign the token.
//
// This package makes the signature when a caller marshals or verifies the token.
// Thus a caller can give the claim options in any sequence. To sign in this
// option includes only the claims that a caller set before it.
func WithSignature(algorithm jwa.Signer, key *jwk.Key, options ...func(*jws.Signature)) func(*Token) error {
	return func(token *Token) error {
		token.pending = append(token.pending, pendingSignature{algorithm, key, options})

		return nil
	}
}

func (token *Token) sign() error {
	tokenType := token.tokenType
	if tokenType == "" {
		tokenType = "JWT"
	}

	if len(token.pending) > 0 {
		for _, check := range token.issuanceChecks {
			if err := check(token); err != nil {
				return err
			}
		}
	}

	for _, pending := range token.pending {
		protectedHeader := &header.Header{Type: tokenType, Algorithm: pending.algorithm}
		signature := &jws.Signature{ProtectedHeader: protectedHeader}

		for _, option := range pending.options {
			option(signature)
		}

		if pending.key != nil {
			for _, candidate := range []*header.Header{protectedHeader, signature.Header} {
				if candidate == nil {
					continue
				}

				if err := pending.key.CheckCertificateChain(candidate.X509CertificateChain); err != nil {
					return err
				}
			}
		}

		encodedProtectedHeader, err := protectedHeader.Marshal()
		if err != nil {
			return err
		}

		protectedHeader.SetEncoded(encodedProtectedHeader)

		encodedPayload, err := token.payload.Marshal()
		if err != nil {
			return err
		}

		var keyMaterial any
		if pending.key != nil {
			keyMaterial = pending.key.Material()
		}

		rawSignature, err := pending.algorithm.Sign(signingInput(encodedProtectedHeader, encodedPayload), keyMaterial)
		if err != nil {
			return err
		}
		signature.Signature = rawSignature

		token.signatures = append(token.signatures, signature)
	}

	token.pending = nil

	return nil
}

// VerificationConfig gives the values that [Token.Verify] accepts.
//
// [NewVerificationConfig] makes one with the options of this package, for example
// [WithAlgorithms] and [WithExpectedIssuer]. [DefaultVerificationConfig] is a
// configuration with the default values.
//
// The zero VerificationConfig accepts the default algorithms and applies the
// default check of "typ": a protected header that carries a media type must
// carry "JWT". It applies no other check of a claim. [WithExpectedType] gives a
// different media type, and [WithAnyType] removes the check.
type VerificationConfig struct {
	algorithms       []jwa.Algorithm
	expectedIssuer   string
	expectedSubject  string
	expectedAudience []string
	leeway           time.Duration

	expectedType string

	maxAge time.Duration

	idStore IDStore

	clock func() time.Time

	rules []Rule

	headerKeys []HeaderKeyPolicy

	requiredAlgorithms []jwa.Algorithm

	allSignatures bool
	anyType       bool
}

var defaultAlgorithms = []jwa.Algorithm{
	jwa.HS256(), jwa.HS384(), jwa.HS512(),
	jwa.RS256(), jwa.RS384(), jwa.RS512(),
	jwa.ES256(), jwa.ES384(), jwa.ES512(),
	jwa.PS256(), jwa.PS384(), jwa.PS512(),
	jwa.EdDSA(), jwa.Ed25519(),
	jwa.MLDSA44(), jwa.MLDSA65(), jwa.MLDSA87(),
}

// NewVerificationConfig returns a [VerificationConfig] with the options applied
// to it. Without options it accepts the default algorithms, which are each
// signature algorithm of this module other than none.
func NewVerificationConfig(options ...func(*VerificationConfig)) VerificationConfig {
	config := VerificationConfig{algorithms: slices.Clone(defaultAlgorithms)}

	for _, option := range options {
		option(&config)
	}

	return config
}

// WithAlgorithms limits verification to the given algorithms.
//
// To give [jwa.None] here accepts unsecured tokens. That is not safe for a
// token from a source that a caller does not trust.
func WithAlgorithms(algorithms ...jwa.Algorithm) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.algorithms = algorithms }
}

// WithExpectedIssuer makes the "iss" claim equal to issuer necessary. Verify
// gives [ErrUnexpectedIssuer] for a different value.
func WithExpectedIssuer(issuer string) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.expectedIssuer = issuer }
}

// WithExpectedAudience makes an "aud" claim that holds one of audience necessary.
// Verify gives [ErrUnexpectedAudience] when the claim holds none of them.
//
// More than one name is for a recipient that answers to more than one name. The
// "aud" claim is an array, and a producer writes the one name that it knows.
// Thus a recipient with two names accepts a token that holds either.
//
// A second call replaces the names of the first. The names are the full set that
// this recipient answers to, and a call that added to that set would make the
// check less strict with no indication.
func WithExpectedAudience(audience ...string) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.expectedAudience = audience }
}

// WithExpectedSubject makes the "sub" claim equal to subject necessary. Verify
// gives [ErrUnexpectedSubject] for a different value.
//
// The "sub" claim is local to the issuer, unless the issuer gives it a global
// value. Thus a recipient that reads two issuers must check "iss" with
// [WithExpectedIssuer] also. To check the subject alone lets one issuer name
// the subject of a different issuer.
func WithExpectedSubject(subject string) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.expectedSubject = subject }
}

// WithExpectedType makes a "typ" header parameter equal to mediaType necessary.
// Verify gives [ErrUnexpectedType] for a different value and for a header with
// no "typ".
//
// This is the explicit typing of RFC 8725 section 3.11, and [WithType] writes
// the value that it reads. A recipient that accepts a profile and a usual JWT at
// one endpoint gives the media type of the profile here. Thus a token of the one
// kind cannot pass as a token of the other kind.
//
// The compare is not case-sensitive, and it supplies "application/" for a value
// with no '/'. Thus "at+jwt", "application/at+jwt" and "AT+JWT" are one media
// type.
//
// Verify reads the "typ" of the protected header that authenticated the token
// and of no other header. See [Token.Type].
func WithExpectedType(mediaType string) func(*VerificationConfig) {
	return func(config *VerificationConfig) {
		config.expectedType = mediaType
		config.anyType = false
	}
}

// WithAnyType removes the check of "typ". Verify then accepts each media type,
// and a header with no "typ".
//
// The default check accepts "JWT" and a header with no "typ". A caller with a
// media type of its own gives [WithExpectedType] and not this option, because
// that option is the check and not the absence of one. This option is for a
// recipient that must accept media types that it does not know first, for
// example a gateway that gives the token to a different component.
//
// A recipient that removes this check must not decide from the token what kind
// of token it is. RFC 8725 section 3.11 gives the confusion that "typ" prevents.
func WithAnyType() func(*VerificationConfig) {
	return func(config *VerificationConfig) {
		config.anyType = true
		config.expectedType = ""
	}
}

// WithMaxAge makes an "iat" claim necessary and limits the age of the token to
// age. Verify gives [ErrTooOld] for a token with a greater age, and
// [ErrIssuedInFuture] for an "iat" claim after the current time. [WithLeeway]
// accepts clock skew in the two checks.
//
// It is different from the "exp" check. "exp" is the time that the producer
// selected, and a producer that gives a long lifetime makes the token good for
// that time. This option is the limit of the recipient, and the recipient
// applies it to each token that it reads. RFC 7519 section 4.1.6 makes "iat"
// available for this: it "can be used to determine the age of the JWT".
//
// An age of zero or less removes the check. A token with no "iat" claim gives
// [ErrMissingRequiredClaim], because a token with no issuance time has no age
// and this package must not report a check that it did not do.
func WithMaxAge(age time.Duration) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.maxAge = age }
}

// WithReplayCheck makes a "jti" claim necessary and gives it to store. Verify
// gives [ErrReplayedToken] for an identifier that store saw before, and it gives
// [ErrMissingRequiredClaim] for a token with no "jti".
//
// RFC 7519 section 4.1.7 makes "jti" the value that "can be used to prevent the
// JWT from being replayed". The claim alone does not prevent a replay. A
// recipient must record the identifiers that it accepted, and this option is
// where that record and verification operate together.
//
// This package supplies no [IDStore]. See that type.
//
// A nil store removes the check.
func WithReplayCheck(store IDStore) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.idStore = store }
}

// WithClock gives the function that verification reads the current time from. The
// default is [time.Now].
//
// It is for a test that must put the current time before or after the "exp" and
// "nbf" claims of a token, and for a caller with a clock of its own. A rule reads
// the same clock with [VerificationConfig.Now].
func WithClock(clock func() time.Time) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.clock = clock }
}

// WithLeeway accepts leeway of clock skew in the checks of "exp" and "nbf".
func WithLeeway(leeway time.Duration) func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.leeway = leeway }
}

// WithAllSignatures makes each signature on the token verify. The default makes
// one signature verify.
//
// It is for a caller that holds the key of each signer and must check that each
// of them signed. A recipient with one key of some keys rejects a correct token
// with this option.
func WithAllSignatures() func(*VerificationConfig) {
	return func(config *VerificationConfig) { config.allSignatures = true }
}

// DefaultVerificationConfig is a [VerificationConfig] with the default values. It
// accepts each signature algorithm of this module other than none, and it applies
// no claim check.
//
// It is a package-level variable, thus a change to it changes each caller in the
// program. Use [NewVerificationConfig] to make a different configuration.
var DefaultVerificationConfig = NewVerificationConfig()

func withKeys(ctx context.Context, source jwk.Source, attempt func(*jwk.KeySet) error) error {
	if source == nil {
		return attempt(nil)
	}

	keySet, err := source.Get(ctx)
	if err != nil {
		return err
	}

	err = attempt(keySet)

	refresher, ok := source.(jwk.Refresher)
	if !ok || !errors.Is(err, jwk.ErrNoSuitableKey) {
		return err
	}

	refreshed, refreshErr := refresher.Refresh(ctx)
	if refreshErr != nil {
		return errors.Join(err, refreshErr)
	}

	return attempt(refreshed)
}

func verifySignature(
	signature *jws.Signature, encodedPayload string, keySet *jwk.KeySet, config VerificationConfig,
) error {
	i := slices.IndexFunc(config.algorithms, func(algorithm jwa.Algorithm) bool {
		return algorithm == signature.ProtectedHeader.Algorithm
	})
	if i == -1 {
		return fmt.Errorf("%w: %v", ErrForbiddenAlgorithm, signature.ProtectedHeader.Algorithm)
	}

	algorithm, ok := config.algorithms[i].(jwa.Verifier)
	if !ok {
		return fmt.Errorf("%w: %v cannot verify", ErrForbiddenAlgorithm, config.algorithms[i])
	}

	encodedProtectedHeader, err := signature.ProtectedHeader.Marshal()
	if err != nil {
		return err
	}

	candidates := keySet.Candidates(
		jwk.Signature, []jwk.Operation{jwk.Verify}, algorithm, signature.ProtectedHeader.KeyID,
	)

	fromHeader, refused, err := headerCandidates(signature.ProtectedHeader, algorithm, config)
	if err != nil {
		return err
	}

	candidates = append(candidates, fromHeader...)

	if len(candidates) == 0 {
		if refused != nil {
			return refused
		}

		return jwk.ErrNoSuitableKey
	}

	failures := make([]error, 0, len(candidates))

	for _, key := range candidates {
		err := algorithm.Verify(signingInput(encodedProtectedHeader, encodedPayload), signature.Signature, key.Material())
		if err == nil {
			return nil
		}

		failures = append(failures, err)
	}

	return fmt.Errorf("%w: %w", ErrUnverified, errors.Join(failures...))
}

func (token *Token) verifySignatures(
	encodedPayload string, keySet *jwk.KeySet, config VerificationConfig,
) error {
	failures := make([]error, 0, len(token.signatures))

	for _, signature := range token.signatures {
		if signature == nil || signature.ProtectedHeader == nil {
			return fmt.Errorf("%w: signature without a protected header", ErrMalformedToken)
		}

		if err := signature.Disjoint(); err != nil {
			return fmt.Errorf("%w: %w", ErrMalformedToken, err)
		}

		err := verifySignature(signature, encodedPayload, keySet, config)

		if config.allSignatures {
			if err != nil {
				return err
			}

			token.authenticatedTypes = append(token.authenticatedTypes, signature.ProtectedHeader.Type)

			continue
		}

		if err == nil {
			token.authenticatedTypes = append(token.authenticatedTypes, signature.ProtectedHeader.Type)

			return nil
		}

		failures = append(failures, err)
	}

	if config.allSignatures {
		return nil
	}

	return fmt.Errorf("%w: %w", ErrUnverified, errors.Join(failures...))
}

// Verify checks the signatures of the token and then its claims. It gives nil
// when the token is satisfactory.
//
// Verify first makes each signature that [WithSignature] recorded, as
// [Token.Marshal] does. Thus a caller that makes a token and then verifies it
// checks a signature that it made. [Token.Pending] gives those signatures
// before Verify makes them.
//
// Verify gets a JWK Set from keys and tries each key of it that is suitable for
// a signature. One signature that verifies is sufficient by default.
// [WithAllSignatures] makes each signature verify.
//
// A *[jwk.KeySet] is a [jwk.Source], thus a caller that holds the keys in memory
// gives the set. A source that is also a [jwk.Refresher], for example a JWK Set
// that this module gets from a server, gets the keys again when no key of the
// first set is suitable, and Verify then makes one more attempt. Thus a
// recipient accepts a token from an issuer that changed its keys, and it does
// not do that operation itself.
//
// Verify gets the keys again for [jwk.ErrNoSuitableKey] only. A signature that
// does not verify under a key that the set holds gives [ErrUnverified], and
// Verify makes no second attempt for it. Thus a sender with a token that no key
// signed cannot make a recipient get the keys again for each such token. The
// limit of the source applies to the "kid" values that remain: a refusal from
// the source is not the error of the token, and Verify reports the error of the
// token with the refusal after it.
//
// An issuer that changes the key material and keeps the "kid" value is the one
// condition that this does not correct. The keys of the set are then suitable,
// and the signature does not verify.
//
// Verify then checks the claims. It gives [ErrExpired] for an "exp" claim
// before the current time, and [ErrNotYetValid] for an "nbf" claim after it. [WithLeeway]
// accepts clock skew in those checks and in the check of "iat". [WithExpectedIssuer],
// [WithExpectedSubject] and [WithExpectedAudience] add checks of "iss", "sub" and
// "aud". [WithMaxAge] limits the age that "iat" gives, and [WithReplayCheck]
// gives "jti" to an [IDStore]. [WithRule] adds the rules of a profile.
//
// Verify also checks the "typ" of the protected header that authenticated the
// token, and it does this with no option. The default accepts a header with no
// "typ" and a header that names a JWT, and it gives [ErrUnexpectedType] for a
// different media type. [WithExpectedType] gives the media type of a profile,
// and [WithAnyType] removes the check.
//
// Verify gives [ErrUnsigned] for a token with no signature, and
// [ErrForbiddenAlgorithm] for a signature with an algorithm that config does not
// accept. A config with no algorithm gets the default algorithms, which are each
// signature algorithm of this module other than none.
func (token *Token) Verify(ctx context.Context, keys jwk.Source, config VerificationConfig) error {
	token.authenticatedTypes = nil

	if err := token.sign(); err != nil {
		return err
	}

	if len(token.signatures) == 0 {
		return ErrUnsigned
	}

	if len(config.algorithms) == 0 {
		config.algorithms = defaultAlgorithms
	}

	if config.requiredAlgorithms != nil {
		config.algorithms = slices.DeleteFunc(
			slices.Clone(config.algorithms),
			func(algorithm jwa.Algorithm) bool {
				return !slices.Contains(config.requiredAlgorithms, algorithm)
			},
		)
	}

	encodedPayload, err := token.payload.Marshal()
	if err != nil {
		return err
	}

	err = withKeys(ctx, keys, func(keySet *jwk.KeySet) error {
		return token.verifySignatures(encodedPayload, keySet, config)
	})
	if err != nil {
		return err
	}

	if err := token.checkClaims(ctx, config); err != nil {
		return err
	}

	token.verified = true

	return nil
}

// Verified reports whether this package authenticated the claims of the token.
//
// It is true after [Token.Verify] gives nil, and after [Token.Decrypt] gives nil.
// The first checks a signature, and the second reads a JWE, whose authenticated
// encryption gives the same property. It is false for a token that [Unmarshal]
// gave and that has met no key, and for a token that a caller made and has not
// signed.
//
// The claim accessors answer before this method is true. This method is not a
// permission that they obey: a token that a caller made holds the claims of that
// caller, and a producer has nothing to verify. It tells a part of a program what
// a different part did.
func (token *Token) Verified() bool { return token.verified }

// ErrMissingRequiredClaim is the error for a token with no claim that a profile
// or a rule makes necessary.
var ErrMissingRequiredClaim = errors.New("jwt: missing a required claim")

func (token *Token) requireClaims(names []string) error {
	present := map[string]bool{
		"iss": token.Issuer() != "",
		"sub": token.Subject() != "",
		"aud": len(token.Audience()) > 0,
		"exp": token.ExpirationTime() != nil,
		"nbf": token.NotBefore() != nil,
		"iat": token.IssuedAt() != nil,
		"jti": token.ID() != "",
	}

	missing := make([]string, 0, len(names))

	for _, name := range names {
		carried, registered := present[name]
		if !registered {
			carried = token.PrivateClaim(name) != nil
		}

		if !carried {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingRequiredClaim, strings.Join(missing, ", "))
	}

	return nil
}

func (token *Token) checkClaims(ctx context.Context, config VerificationConfig) error {
	for _, rule := range config.rules {
		if err := rule(ctx, token, config); err != nil {
			return err
		}
	}

	now := config.Now()

	if token.ExpirationTime() != nil && now.After(token.ExpirationTime().Add(config.leeway)) {
		return ErrExpired
	}

	if token.NotBefore() != nil && now.Before(token.NotBefore().Add(-config.leeway)) {
		return ErrNotYetValid
	}

	if config.expectedIssuer != "" && token.Issuer() != config.expectedIssuer {
		return fmt.Errorf("%w: got %q, want %q", ErrUnexpectedIssuer, token.Issuer(), config.expectedIssuer)
	}

	if len(config.expectedAudience) > 0 && !slices.ContainsFunc(
		config.expectedAudience,
		func(audience string) bool { return slices.Contains(token.Audience(), audience) },
	) {
		return fmt.Errorf("%w: want one of %q", ErrUnexpectedAudience, config.expectedAudience)
	}

	if config.expectedSubject != "" && token.Subject() != config.expectedSubject {
		return fmt.Errorf("%w: want %q", ErrUnexpectedSubject, config.expectedSubject)
	}

	if err := token.checkType(config); err != nil {
		return err
	}

	if err := token.checkAge(now, config); err != nil {
		return err
	}

	return token.checkReplay(ctx, config)
}

func (token *Token) checkType(config VerificationConfig) error {
	if config.anyType {
		return nil
	}

	for _, mediaType := range token.authenticatedTypes {
		if config.expectedType == "" {
			if mediaType == "" || equalMediaType(mediaType, "JWT") {
				continue
			}

			return fmt.Errorf(
				"%w: %q, and no expected type; see WithExpectedType and WithAnyType",
				ErrUnexpectedType, mediaType,
			)
		}

		if !equalMediaType(mediaType, config.expectedType) {
			return fmt.Errorf(
				"%w: got %q, want %q", ErrUnexpectedType, mediaType, config.expectedType,
			)
		}
	}

	return nil
}

func (token *Token) checkAge(now time.Time, config VerificationConfig) error {
	if config.maxAge <= 0 {
		return nil
	}

	issuedAt := token.IssuedAt()
	if issuedAt == nil {
		return fmt.Errorf("%w: iat", ErrMissingRequiredClaim)
	}

	if issuedAt.After(now.Add(config.leeway)) {
		return ErrIssuedInFuture
	}

	if now.After(issuedAt.Add(config.maxAge).Add(config.leeway)) {
		return ErrTooOld
	}

	return nil
}

func (token *Token) checkReplay(ctx context.Context, config VerificationConfig) error {
	if config.idStore == nil {
		return nil
	}

	id := token.ID()
	if id == "" {
		return fmt.Errorf("%w: jti", ErrMissingRequiredClaim)
	}

	unused, err := config.idStore.Record(ctx, id, token.ExpirationTime())
	if err != nil {
		return fmt.Errorf("jwt: replay check: %w", err)
	}

	if !unused {
		return ErrReplayedToken
	}

	return nil
}

// Marshal returns the compact serialization of the token. It gives a JWE with
// five parts when a caller gives [WithEncryption], and a JWS with three parts in
// each other condition.
//
// Marshal makes each signature that [WithSignature] recorded. It gives
// [ErrUnsigned] for a token with no signature, and [ErrMultipleSignatures] for a
// token with more than one signature. The compact serialization holds one
// signature only. Use [Token.MarshalJSON] for a token with more signatures.
func (token *Token) Marshal() (string, error) {
	if token.pendingEncryption != nil || token.message != nil {
		return token.marshalEncrypted()
	}

	if err := token.sign(); err != nil {
		return "", err
	}

	switch len(token.signatures) {
	case 0:
		return "", ErrUnsigned
	case 1:
	default:
		return "", ErrMultipleSignatures
	}

	signature := token.signatures[0]

	encodedProtectedHeader, err := signature.ProtectedHeader.Marshal()
	if err != nil {
		return "", err
	}

	encodedPayload, err := token.payload.Marshal()
	if err != nil {
		return "", err
	}

	return encodedProtectedHeader + "." + encodedPayload + "." + signature.String(), nil
}

// String returns the compact serialization of the token. It panics where
// [Token.Marshal] gives an error. A caller with a token that it does not trust,
// or with an unsigned token, must use [Token.Marshal].
func (token *Token) String() string {
	encodedToken, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	return encodedToken
}

// Unmarshal reads a JWT in one of the two compact serializations.
//
// A count of parts tells the two apart. A JWS has three parts and a JWE has
// five parts. Unmarshal gives a token with five parts in its encrypted
// condition, because there is no key here. Its claims are not available until
// [Token.Decrypt] supplies a key.
//
// Unmarshal does no verification. There is no key here, thus it cannot do any.
// The claim accessors of the token that it gives answer with the claims that came
// in, and those are the claims of the producer of the octets and not facts. A
// caller applies [Token.Verify], or [Token.Decrypt] for a JWE, before a decision
// on them. [Token.Verified] tells whether one of the two happened.
func Unmarshal(token string) (*Token, error) {
	parts := strings.Count(token, ".") + 1

	if parts == 5 {
		message, err := jwe.Unmarshal(token)
		if err != nil {
			return nil, err
		}

		return &Token{payload: new(payload), message: message}, nil
	}

	if parts != 3 {
		return nil, fmt.Errorf("%w: got %d parts, want 3 or 5", ErrMalformedToken, parts)
	}

	encodedHeader, rest, _ := strings.Cut(token, ".")
	encodedPayload, encodedSignature, _ := strings.Cut(rest, ".")

	signature := new(jws.Signature)
	if err := signature.Unmarshal(encodedHeader, encodedSignature); err != nil {
		return nil, err
	}

	payload := new(payload)
	if err := payload.Unmarshal(encodedPayload); err != nil {
		return nil, err
	}

	return &Token{payload: payload, signatures: []*jws.Signature{signature}}, nil
}

type rawToken struct {
	Payload string `json:"payload"`

	// Signatures is the "signatures" array of the general syntax.
	Signatures []*jws.Signature `json:"signatures,omitempty"`

	// ProtectedHeader, Header and Signature are the one signature that the
	// flattened syntax moves up into the top-level object.
	//
	// The three are octets and not their decoded types. MarshalJSON puts the
	// encoding that [jws.Signature] makes into them, and UnmarshalJSON gives the
	// whole document to that same type. Thus the checks that
	// [jws.Signature] makes stay on the path in each direction.
	ProtectedHeader jsontext.Value `json:"protected,omitempty"`
	Header          jsontext.Value `json:"header,omitempty"`
	Signature       jsontext.Value `json:"signature,omitempty"`
}

// MarshalJSON encodes the token as the JWS JSON Serialization. It writes the
// flattened serialization for a token with one signature, and the general
// serialization for a token with more signatures.
//
// An encrypted token gets the JWE JSON Serialization. Its claims are in the
// ciphertext, thus there is no "payload" member to write.
func (token *Token) MarshalJSON() ([]byte, error) {
	if token.pendingEncryption != nil || token.message != nil {
		if err := token.encrypt(); err != nil {
			return nil, err
		}

		return json.Marshal(token.message)
	}

	if err := token.sign(); err != nil {
		return nil, err
	}

	if token.payload == nil {
		return nil, fmt.Errorf("%w: no payload", ErrMalformedToken)
	}

	encodedPayload, err := token.payload.Marshal()
	if err != nil {
		return nil, err
	}

	switch len(token.signatures) {
	case 0:
		return nil, ErrUnsigned
	case 1:
		signature := token.signatures[0]
		if signature == nil || signature.ProtectedHeader == nil {
			return nil, fmt.Errorf("%w: signature without a protected header", ErrMalformedToken)
		}

		encodedSignature, err := json.Marshal(signature)
		if err != nil {
			return nil, err
		}

		flattenedToken := rawToken{Payload: encodedPayload}
		if err := json.Unmarshal(encodedSignature, &flattenedToken); err != nil {
			return nil, err
		}

		return json.Marshal(&flattenedToken)
	default:
		return json.Marshal(&rawToken{Payload: encodedPayload, Signatures: token.signatures})
	}
}

// UnmarshalJSON reads the general or the flattened JWS JSON Serialization. It
// finds which serialization came in from the members of the object.
//
// UnmarshalJSON gives [ErrMalformedToken] for an object that is not one of the
// two serializations, and [jsontext.ErrDuplicateName] for a member name two
// times in one of the objects.
func (token *Token) UnmarshalJSON(data []byte) error {
	rawToken := new(rawToken)

	if err := json.Unmarshal(data, rawToken); err != nil {
		return jsonerr.KeepDuplicateName(err)
	}

	if rawToken.Payload == "" {
		return fmt.Errorf("%w: missing payload", ErrMalformedToken)
	}

	payload := new(payload)
	if err := payload.Unmarshal(rawToken.Payload); err != nil {
		return err
	}

	if (len(rawToken.ProtectedHeader) != 0 || len(rawToken.Header) != 0 || len(rawToken.Signature) != 0) &&
		len(rawToken.Signatures) != 0 {
		return fmt.Errorf(
			"%w: document uses both the flattened and the general JWS JSON Serialization syntax", ErrMalformedToken,
		)
	}

	var signatures []*jws.Signature

	if (len(rawToken.ProtectedHeader) != 0 || len(rawToken.Header) != 0) && len(rawToken.Signature) != 0 {
		signature := new(jws.Signature)
		if err := signature.UnmarshalJSON(data); err != nil {
			return err
		}

		signatures = append(signatures, signature)
	} else {
		signatures = rawToken.Signatures
	}

	if len(signatures) == 0 {
		return ErrUnsigned
	}

	for _, signature := range signatures {
		if signature == nil || signature.ProtectedHeader == nil {
			return fmt.Errorf("%w: signature without a protected header", ErrMalformedToken)
		}
	}

	token.payload = payload
	token.signatures = signatures
	token.pending = nil

	return nil
}
