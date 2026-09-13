package jwt

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"

	"github.com/iscultas/jwt-go/jwk"
)

// ConfirmationClaim is the name of the confirmation claim.
//
// This package keeps the claim in the private claims map, and not as a field of
// the payload. That map holds each claim that is not a registered claim. This
// is a property of the representation, and not of the position of the claim.
const ConfirmationClaim = "cnf"

// ThumbprintConfirmation is the "jkt" confirmation method. It is a member of
// the "cnf" claim, and not a different claim.
//
// It is here with the four members, because a claim is one JSON object. A
// caller that assembles the claim must not collect its members from two
// packages. The IR records which document gives which member. The comment on
// [Confirmation.Thumbprint] also records it.
const ThumbprintConfirmation = "jkt"

var (
	// ErrMultipleConfirmationKeys is the error for a "cnf" claim that names more
	// than one proof-of-possession key. RFC 7800 section 3.1 gives the rule: "The
	// "cnf" claim value MUST represent only a single proof-of-possession key;
	// thus, at most one of the "jwk", "jwe", and "jku" (JWK Set URL)
	// confirmation values defined below may be present."
	//
	// "kid" is not in that list, and this is correct. It can come with "jku", and
	// section 3.5 makes it necessary when the JWK Set holds more than one key.
	ErrMultipleConfirmationKeys = errors.New("jwt: cnf names more than one key")

	// ErrUnprotectedConfirmationKey is the error for a symmetric key in the
	// "jwk" member of a token that is not encrypted.
	//
	// RFC 7800 section 3.2 lets the member hold such a key only "provided that
	// the JWT is encrypted so that the key is not revealed to unintended
	// parties". It also gives the alternative: "If the JWT is not encrypted, the
	// symmetric key MUST be encrypted as described below", which puts the key in
	// the "jwe" member.
	//
	// This error prevents a signed JWT that each reader can read and that
	// publishes the secret whose possession it asks a party to prove.
	ErrUnprotectedConfirmationKey = errors.New("jwt: cnf carries a symmetric key in an unencrypted token")

	// ErrUnidentifiedPresenter is the error for a token with a "cnf" claim that
	// names no subject and no issuer. RFC 7800 section 3 gives the rule: "At
	// least one of the "sub" and "iss" claims MUST be present in the JWT."
	//
	// The claim says that a presenter holds a key. A token that does not name the
	// presenter gives possession to nobody.
	ErrUnidentifiedPresenter = errors.New("jwt: cnf without a sub or iss claim")

	// ErrMalformedConfirmation is the error for a "cnf" claim that is not a JSON
	// object, or with members that do not have the types of their definitions.
	ErrMalformedConfirmation = errors.New("jwt: malformed cnf claim")
)

// Confirmation is the value of a "cnf" claim. It holds the procedures that name
// the key. A presenter must show possession of that key.
//
// The caller can set one of JWK, EncryptedKey and KeySetURL, and no more. This
// is the single-key rule. KeyID can come with one of them, or without them.
// Thumbprint is the same.
//
// The zero Confirmation names no key.
type Confirmation struct {
	// JWK is the "jwk" member of section 3.2. It holds the public key of the
	// asymmetric private key that the presenter holds. In an encrypted token only,
	// it can hold a symmetric key.
	JWK *jwk.Key

	// EncryptedKey is the "jwe" member of section 3.3. It holds a symmetric key
	// as a JWE Compact Serialization, encrypted to a key that the recipient
	// holds.
	//
	// This package keeps the string that came in and does not decrypt it. The key
	// in it is a proof-of-possession secret, and its use belongs to the
	// application. Nothing in this package knows which key opens it that the
	// caller cannot use with the jwe package. This field gives the caller that
	// ability.
	EncryptedKey string

	// KeySetURL is the "jku" member of section 3.5. It is a URI that names a JWK
	// Set with the key.
	//
	// This package parses the URI and keeps it. It never gets the resource. The
	// non-test source of this module has no networking import. "jku" and "x5u"
	// have the same position in a JOSE header.
	KeySetURL *url.URL

	// KeyID is the "kid" member of section 3.4. It names a key that the recipient
	// can already get. Section 3.5 also makes it necessary with a "jku" whose JWK
	// Set holds more than one key.
	KeyID string

	// Thumbprint is the "jkt" member of RFC 9449 section 6.1, and not of
	// RFC 7800. That section gives it as "the base64url encoding ... of the JWK
	// SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK
	// format) to which the access token is bound".
	//
	// [jwk.Key.ThumbprintID] with [crypto.SHA256] makes the same string from a
	// key. A caller that binds a token to a key uses that method to fill in this
	// field.
	Thumbprint string
}

func (confirmation *Confirmation) keys() int {
	present := 0

	for _, set := range []bool{
		confirmation.JWK != nil,
		confirmation.EncryptedKey != "",
		confirmation.KeySetURL != nil,
	} {
		if set {
			present++
		}
	}

	return present
}

func (confirmation *Confirmation) members() map[string]any {
	members := make(map[string]any, 5)

	if confirmation.JWK != nil {
		members["jwk"] = confirmation.JWK
	}

	if confirmation.EncryptedKey != "" {
		members["jwe"] = confirmation.EncryptedKey
	}

	if confirmation.KeySetURL != nil {
		members["jku"] = confirmation.KeySetURL.String()
	}

	if confirmation.KeyID != "" {
		members["kid"] = confirmation.KeyID
	}

	if confirmation.Thumbprint != "" {
		members[ThumbprintConfirmation] = confirmation.Thumbprint
	}

	return members
}

// WithConfirmation gives the key of this token. The presenter must show
// possession of that key. WithConfirmation sets the "cnf" claim.
//
// WithConfirmation applies the single-key rule here, where the error of the
// caller is, and not at the time of the signature. It gives
// [ErrMultipleConfirmationKeys] for more than one key.
//
// Two other rules apply to the other parts of the token. A symmetric key makes
// an encrypted token necessary, and a "sub" or an "iss" claim must be present. This
// package applies those rules when it signs the token, because a caller can give
// the options that obey them in any sequence. See
// [ErrUnprotectedConfirmationKey] and [ErrUnidentifiedPresenter].
func WithConfirmation(confirmation Confirmation) func(*Token) error {
	return func(token *Token) error {
		if confirmation.keys() > 1 {
			return ErrMultipleConfirmationKeys
		}

		token.payload.setPrivateClaim(ConfirmationClaim, confirmation.members())
		token.issuanceChecks = append(token.issuanceChecks, (*Token).checkConfirmationIssuance)

		return nil
	}
}

func (token *Token) checkConfirmationIssuance() error {
	if token.Subject() == "" && token.Issuer() == "" {
		return ErrUnidentifiedPresenter
	}

	confirmation, err := token.Confirmation()
	if err != nil {
		return err
	}

	if confirmation != nil && confirmation.JWK != nil &&
		confirmation.JWK.Type() == jwk.OctetSequence && token.pendingEncryption == nil {
		return ErrUnprotectedConfirmationKey
	}

	return nil
}

// Confirmation returns the "cnf" claim of the token. It gives nil when the token
// has no such claim.
//
// Confirmation ignores each member that this package does not give, and does not
// reject it. RFC 7800 section 3.1 gives this rule: "in the absence of such
// requirements, all confirmation members that are not understood by
// implementations MUST be ignored".
//
// Confirmation applies the single-key rule in the two directions. Thus a "cnf"
// claim that names two keys gives [ErrMultipleConfirmationKeys], and this package
// does not select one of the two with no indication.
func (token *Token) Confirmation() (*Confirmation, error) {
	claim := token.PrivateClaim(ConfirmationClaim)
	if claim == nil {
		return nil, nil
	}

	members, ok := claim.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %T is not a JSON object", ErrMalformedConfirmation, claim)
	}

	confirmation := &Confirmation{}

	for _, field := range []struct {
		name  string
		value *string
	}{
		{"jwe", &confirmation.EncryptedKey},
		{"kid", &confirmation.KeyID},
		{ThumbprintConfirmation, &confirmation.Thumbprint},
	} {
		value, err := stringClaim(members, field.name)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedConfirmation, err)
		}

		*field.value = value
	}

	if raw, present := members["jku"]; present {
		reference, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%w: jku is %T, not a string", ErrMalformedConfirmation, raw)
		}

		parsed, err := url.Parse(reference)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedConfirmation, err)
		}

		confirmation.KeySetURL = parsed
	}

	key, err := confirmationKey(members)
	if err != nil {
		return nil, err
	}

	confirmation.JWK = key

	if confirmation.keys() > 1 {
		return nil, ErrMultipleConfirmationKeys
	}

	return confirmation, nil
}

func confirmationKey(members map[string]any) (*jwk.Key, error) {
	raw, present := members["jwk"]
	if !present {
		return nil, nil
	}

	if key, ok := raw.(*jwk.Key); ok {
		return key, nil
	}

	object, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedConfirmation, err)
	}

	key := &jwk.Key{}
	if err := json.Unmarshal(object, key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedConfirmation, err)
	}

	return key, nil
}
