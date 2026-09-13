package jwt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
	"github.com/iscultas/jwt-go/jws"
)

var (
	// ErrNoSuchSignature is the error from [Token.AddProtectedHeader] for an
	// index that names no pending signature.
	ErrNoSuchSignature = errors.New("jwt: no pending signature at that index")

	// ErrUnverifiableSignature is the error from [Token.VerifySignature] for a
	// signature with no protected header. Such a signature cannot give its
	// properties, and this is a defect in the token. It is not a key that the
	// caller does not hold.
	ErrUnverifiableSignature = errors.New("jwt: signature without a protected header")
)

// Rule is a check that this package applies to a token after it authenticates
// that token.
//
// A Rule operates after each signature verifies, and before the time, issuer and
// audience checks. Thus a rule can accept the values that it reads, and a claim
// that it rejects is a claim that the signer made.
//
// The [VerificationConfig] that a rule gets is the configuration of the caller.
// Thus a rule can operate with the policy with it. It can obey the leeway of
// the caller, or reject the token when the caller gave no expected audience that
// the profile makes necessary.
//
// A rule can make a value necessary that the caller cannot give through this configuration.
// Examples are the HTTP method of a request and a nonce that the server made.
// Such a rule gets the value as an argument to its option, and it keeps that
// value. This package sees no request, thus it cannot supply that value.
//
// The context is the context of the caller of [Token.Verify]. A rule that reads
// a key set or that makes a request gives it to that operation. Thus the caller
// can stop a verification that one of its rules made slow.
type Rule func(ctx context.Context, token *Token, config VerificationConfig) error

// WithRule applies rules with the usual claim checks.
//
// The rules collect in the sequence that the caller gives, and each rule must
// accept the token. Two options that request for different profiles give the two
// rules. It does not give a result with no indication, where only the last rule
// applies.
// This package does not find that the two rules are compatible.
func WithRule(rules ...Rule) func(*VerificationConfig) {
	return func(config *VerificationConfig) {
		config.rules = append(config.rules, rules...)
	}
}

// WithRequiredAlgorithms makes the permitted algorithms less, and does not
// replace them. The result is the intersection with the [WithAlgorithms] value of
// the caller.
//
// This package applies the limit after each option operates. Thus the limit holds for
// each sequence of the two options, and that is the function of this option. A
// profile that rejects MAC algorithms must reject them also when the caller gave
// [WithAlgorithms] last. An option that only replaced the list is not correct
// in that sequence.
//
// This option cannot make the permitted algorithms more. An algorithm that the
// caller did not accept stays out.
func WithRequiredAlgorithms(algorithms ...jwa.Algorithm) func(*VerificationConfig) {
	return func(config *VerificationConfig) {
		config.requiredAlgorithms = append(config.requiredAlgorithms, algorithms...)
	}
}

// Algorithms returns the signature algorithms that verification accepts, before
// this package applies the limit of [WithRequiredAlgorithms].
func (config VerificationConfig) Algorithms() []jwa.Algorithm {
	return slices.Clone(config.algorithms)
}

// ExpectedIssuer returns the issuer that [WithExpectedIssuer] gave. It is empty
// when the caller gave none.
//
// A profile with a specification that makes the recipient know the issuer reads this
// method. Such a profile rejects the token when the value is empty. The
// alternative does the other checks and does not do this one with no indication. To
// report conformance and not to do the check is the failure that this method
// lets a profile prevent.
func (config VerificationConfig) ExpectedIssuer() string { return config.expectedIssuer }

// ExpectedAudience returns the names that [WithExpectedAudience] gave. The result
// is empty when the caller gave none. See [VerificationConfig.ExpectedIssuer].
//
// The result is a copy, thus a rule cannot change the policy of the caller
// through it.
func (config VerificationConfig) ExpectedAudience() []string {
	return slices.Clone(config.expectedAudience)
}

// Now returns the current time from the clock that [WithClock] gave. It gives the
// time of [time.Now] when the caller gave no clock.
//
// A rule with a time check reads this method and does not read time.Now. Thus the
// rule and this package read one clock, and a test that moves the clock moves the
// two together.
func (config VerificationConfig) Now() time.Time {
	if config.clock == nil {
		return time.Now()
	}

	return config.clock()
}

// Leeway returns the clock skew that [WithLeeway] accepts. Thus a rule with a
// time check applies the same tolerance as this package.
func (config VerificationConfig) Leeway() time.Duration { return config.leeway }

// ExpectedSubject returns the subject that [WithExpectedSubject] gave. It is
// empty when the caller gave none. See [VerificationConfig.ExpectedIssuer].
func (config VerificationConfig) ExpectedSubject() string { return config.expectedSubject }

// ExpectedType returns the media type that [WithExpectedType] gave. It is empty
// when the caller gave none, which is the default check against "JWT", and also
// when the caller gave [WithAnyType].
//
// A profile with a media type of its own reads this method and rejects the token
// when the value is not its own. Thus the profile does not report explicit
// typing while the recipient accepts a usual JWT. See
// [VerificationConfig.ExpectedIssuer].
func (config VerificationConfig) ExpectedType() string { return config.expectedType }

// MaxAge returns the age limit that [WithMaxAge] gave. It is zero when the
// caller gave none, and a rule that needs a limit rejects that.
func (config VerificationConfig) MaxAge() time.Duration { return config.maxAge }

// IDStore records the "jti" values that this recipient accepted.
// [WithReplayCheck] gives one to verification. Its function is to prevent a
// replay of a token that is still in its lifetime.
//
// This package supplies no implementation, and this is intentional. A store must
// keep an entry for as long as a token can use it again, it must be correct when
// two recipients read it at one time, and it must forget an entry that no token
// can use. Those three properties are properties of a deployment: one process
// with a map, some processes with a shared cache, and a database are three
// different answers, and this package cannot select among them. This is the same
// division that [Rule] and [IssuanceRule] make: the times and the readers are
// here, and what a profile does with them is not.
//
// A Record that gives an error stops the verification. Thus a store that cannot
// answer does not let a token pass unchecked.
type IDStore interface {
	// Record reports whether id is new. It gives false for an id that a previous
	// verification accepted.
	//
	// expiration is the "exp" claim of the token, and it is nil for a token with
	// no such claim. An implementation can forget an entry after that time,
	// because a token after its expiration gives [ErrExpired] and never reaches
	// this method. A nil expiration gives no such limit.
	//
	// Record writes the entry and reports on it in one operation. Two methods,
	// where one asks and one writes, let two recipients that read the same store
	// accept one token two times.
	Record(ctx context.Context, id string, expiration *time.Time) (bool, error)
}

// IssuanceRule is a producer-side check of a profile. This package operates it one
// time, before it makes any signature.
//
// It operates before and not after. Thus this package does not write a token
// that one of the rules rejects. It also does not write the token first and
// then find the error.
//
// A rule can also complete the token that it checks. That is the function of
// [Token.AddProtectedHeader]. A header parameter that comes from the signature
// key is not a value that the caller can give. The same options select the key,
// and in any sequence.
type IssuanceRule func(*Token) error

// WithIssuanceRule applies rules when this package signs the token.
//
// The rules operate only for a token that this package signs. An unsigned [Token] is
// a claims set that no profile uses. To apply the rules of a profile to it
// rejects a value that gives no data.
func WithIssuanceRule(rules ...IssuanceRule) func(*Token) error {
	return func(token *Token) error {
		token.issuanceChecks = append(token.issuanceChecks, rules...)

		return nil
	}
}

// WithType sets the "typ" value of each protected header on this token. The
// default is empty, which is "JWT".
//
// This option is the full procedure by which a profile with a media type puts
// that type in the token. It also gives the explicit typing of RFC 8725
// section 3.11. A recipient can then see the difference between a token of that
// profile and a usual JWT. That difference makes the two safe to accept at one
// endpoint.
//
// [WithExpectedType] is the verifying half. A profile that writes a media type
// here and does not read it there gets no part of that safety: it marks its
// tokens and accepts each other token also. By default a recipient that gives
// neither option rejects a media type that is not "JWT", thus a token of a
// profile does not pass as a usual JWT.
func WithType(tokenType string) func(*Token) error {
	return func(token *Token) error {
		token.tokenType = tokenType

		return nil
	}
}

// Type returns the "typ" value that [WithType] set. Each protected header that
// this package makes will hold that value, and an empty value is "JWT".
//
// Type gives the zero value for a token that [Unmarshal] or
// [Token.UnmarshalJSON] read. Type does not read the protected headers, thus a
// "typ" value in them does not show here.
//
// To make verification check the media type, give [WithExpectedType]. It reads
// the header that authenticated the token, which is the check that a recipient
// needs.
//
// To read the media type of such a token, examine ProtectedHeader.Type of each
// signature in [Token.Signatures]. The "typ" parameter is in the protected
// header, thus each signature has a value of its own. [Token.Verify] accepts
// one signature of many by default. Thus a [Rule] must examine each signature,
// because one value for the token can come from a signature that did not
// verify.
func (token *Token) Type() string { return token.tokenType }

// Signatures returns the signatures of the token. Thus a rule can read the
// protected header that it must check, which holds "typ", "alg", "jwk", "kid"
// and "x5c".
//
// The slice is a copy, thus a rule cannot add or remove a signature. The
// signatures  are part of the token, because a rule that must check a
// header parameter must read it.
//
// The result is empty until this package signs the token. In a [Rule] it always
// holds the signatures, because [Token.Verify] makes each pending signature
// before it verifies.
func (token *Token) Signatures() []*jws.Signature { return slices.Clone(token.signatures) }

// RequireClaims reports each name that the token does not hold, as one
// [ErrMissingRequiredClaim] that names all of them.
//
// It gives all of them and not the first one. A caller that did not give three claims
// must get the three names, and not three tries.
//
// RequireClaims looks for each name in the seven fields, and then in the
// private claims map. Thus a profile can make "client_id" or "htm" necessary by
// name. This package has no data about the two names.
func (token *Token) RequireClaims(names ...string) error { return token.requireClaims(names) }

// Signing gives the properties of a signature that the token will make and has
// not made.
type Signing struct {
	// Algorithm is the algorithm that [WithSignature] named.
	Algorithm jwa.Signer

	// Key is the key of the signature. It is nil for an algorithm that needs no
	// key.
	Key *jwk.Key
}

// Pending returns the signatures that the token will make. Thus an issuance rule
// can reject an algorithm before this package uses it.
//
// A profile that rejects "none", or that rejects MAC algorithms, gives that rule
// here. The same check on the output is not equal to this one. The signature
// is available at that time, and this package made a token that it must not make.
func (token *Token) Pending() []Signing {
	pending := make([]Signing, 0, len(token.pending))

	for _, signature := range token.pending {
		pending = append(pending, Signing{Algorithm: signature.algorithm, Key: signature.key})
	}

	return pending
}

// AddProtectedHeader adds parameters to the protected header of one pending
// signature. The index i is the position in the result of [Token.Pending].
//
// It operates on one signature and not on all of them together. The parameter
// that a profile adds usually comes from the key of that signature.
//
// To write the key of one signature into the header of a different signature
// makes a document. The header of that document does not agree with its
// signature. Such a token is not more careful. It is incorrect.
//
// This method adds the parameters, and does not replace them. Thus a protected
// header that the caller gave through [WithSignature] stays. This package
// applies the parameters when it makes the signature. That is the cause of the
// cause to call this method from an issuance rule: the header does not be available at
// that time.
//
// AddProtectedHeader gives [ErrNoSuchSignature] for an index that names no
// pending signature.
func (token *Token) AddProtectedHeader(i int, options ...func(*header.Header)) error {
	if i < 0 || i >= len(token.pending) {
		return fmt.Errorf("%w: %d", ErrNoSuchSignature, i)
	}

	token.pending[i].options = append(token.pending[i].options, jws.WithProtectedHeader(options...))

	return nil
}

// VerifySignature checks one signature against one key set with config. It gives
// nil when the signature verifies.
//
// A profile must use this method when its specification names the key, and does not
// let the recipient select it. A signature that verifies shows only that one key
// of the recipient was the key of the signer. A profile that makes one
// key necessary must make that check independently, and this method is the
// procedure. It uses one signature verification, and it gives a statement that
// is true and not only possible.
//
// The algorithm policy and the header-key policies of config apply. Thus a rule
// cannot use a key that the policy of the caller removed.
//
// VerifySignature gets the keys as [Token.Verify] does, and it gets them again
// one time when the source is a [jwk.Refresher] and no key of the first set is
// suitable.
//
// VerifySignature gives [ErrUnverifiableSignature] for a signature with no
// protected header.
func (token *Token) VerifySignature(
	ctx context.Context, signature *jws.Signature, keys jwk.Source, config VerificationConfig,
) error {
	if signature == nil || signature.ProtectedHeader == nil {
		return ErrUnverifiableSignature
	}

	encodedPayload, err := token.payload.Marshal()
	if err != nil {
		return err
	}

	return withKeys(ctx, keys, func(keySet *jwk.KeySet) error {
		return verifySignature(signature, encodedPayload, keySet, config)
	})
}
