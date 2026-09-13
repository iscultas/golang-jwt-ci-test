package jwt

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"

	"github.com/iscultas/jwt-go/header"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwe"
	"github.com/iscultas/jwt-go/jwk"
)

// NestedContentType is the "cty" value that RFC 7519 section 5.2 makes necessary
// on a Nested JWT: "This Header Parameter MUST be present and its value MUST be
// JWT."
//
// It tells a recipient that the plaintext is one more JWT and not a claims set.
// Thus it also tells the recipient if a signature is in the plaintext.
//
// This package writes this value. It accepts more values. See [isNested].
const NestedContentType = "JWT"

func isNested(contentType string) bool {
	return equalMediaType(contentType, NestedContentType)
}

type encrypting struct {
	algorithm  jwa.KeyEncrypter
	encryption jwa.ContentEncrypter
	key        *jwk.Key
	options    []func(*header.Header)
}

// ErrUnencrypted is the error from [Token.Decrypt] for a token that this package
// not encrypted.
var ErrUnencrypted = errors.New("jwt: token is not encrypted")

// ErrForbiddenKeyManagement is the error for a JWE that names an "alg" or "enc"
// value which the [DecryptionConfig] does not accept.
//
// It is the counterpart of [ErrForbiddenAlgorithm], for the same cause. A token
// that selects the algorithms must not be able to select an algorithm that the
// recipient does not select.
var ErrForbiddenKeyManagement = errors.New("jwt: forbidden key management algorithm")

// WithEncryption records that this package must encrypt the token. As
// [WithSignature] does, it does the work at serialization time. Thus a caller can
// give the claim options in any sequence.
//
// With [WithSignature] it makes a Nested JWT. This package signs the token, and
// the JWS is then the plaintext of the JWE. RFC 7519 section 11.2 gives that
// sequence: "if signing and encryption are both to be applied, the producer MUST
// sign the message first and then encrypt the result". A signature on a
// ciphertext shows only that the signer saw the ciphertext. A signature below the
// encryption shows that the signer accepted the claims.
func WithEncryption(
	algorithm jwa.KeyEncrypter,
	encryption jwa.ContentEncrypter,
	key *jwk.Key,
	options ...func(*header.Header),
) func(*Token) error {
	return func(token *Token) error {
		token.pendingEncryption = &encrypting{algorithm, encryption, key, options}

		return nil
	}
}

func (token *Token) encrypt() error {
	if token.pendingEncryption == nil {
		return nil
	}

	pending := token.pendingEncryption

	protectedHeader := &header.Header{
		Type:                "JWT",
		Algorithm:           pending.algorithm,
		EncryptionAlgorithm: pending.encryption,
	}

	for _, option := range pending.options {
		option(protectedHeader)
	}

	plaintext, err := token.plaintext(protectedHeader)
	if err != nil {
		return err
	}

	var keyMaterial any
	if pending.key != nil {
		keyMaterial = pending.key.Material()
	}

	message := &jwe.Message{ProtectedHeader: protectedHeader}
	if err := message.Encrypt(plaintext, keyMaterial); err != nil {
		return err
	}

	token.message = message
	token.pendingEncryption = nil

	return nil
}

func (token *Token) plaintext(protectedHeader *header.Header) ([]byte, error) {
	if len(token.pending) == 0 && len(token.signatures) == 0 {
		return json.Marshal(&token.payload.claims, json.Deterministic(true))
	}

	if err := token.sign(); err != nil {
		return nil, err
	}

	if len(token.signatures) != 1 {
		return nil, ErrMultipleSignatures
	}

	signature := token.signatures[0]

	encodedProtectedHeader, err := signature.ProtectedHeader.Marshal()
	if err != nil {
		return nil, err
	}

	encodedPayload, err := token.payload.Marshal()
	if err != nil {
		return nil, err
	}

	protectedHeader.ContentType = NestedContentType

	return append(signingInput(encodedProtectedHeader, encodedPayload), "."+signature.String()...), nil
}

func (token *Token) marshalEncrypted() (string, error) {
	if err := token.encrypt(); err != nil {
		return "", err
	}

	return token.message.Marshal()
}

// DecryptionConfig adds to [VerificationConfig] the key management and content
// encryption algorithms that a recipient accepts.
//
// [NewDecryptionConfig] makes one with the options of this package, for example
// [WithKeyManagementAlgorithms]. [DefaultDecryptionConfig] is a configuration
// with the default values.
type DecryptionConfig struct {
	VerificationConfig

	keyManagement      []jwa.Algorithm
	contentEncryption  []jwa.Algorithm
	requireNestedToken bool
}

var defaultKeyManagementAlgorithms = []jwa.Algorithm{
	jwa.Dir(),
	jwa.RSAOAEP(), jwa.RSAOAEP256(),
	jwa.A128KW(), jwa.A192KW(), jwa.A256KW(),
	jwa.A128GCMKW(), jwa.A192GCMKW(), jwa.A256GCMKW(),
	jwa.ECDHES(), jwa.ECDHESA128KW(), jwa.ECDHESA192KW(), jwa.ECDHESA256KW(),
	jwa.PBES2HS256A128KW(), jwa.PBES2HS384A192KW(), jwa.PBES2HS512A256KW(),
}

var defaultContentEncryptionAlgorithms = []jwa.Algorithm{
	jwa.A128CBCHS256(), jwa.A192CBCHS384(), jwa.A256CBCHS512(),
	jwa.A128GCM(), jwa.A192GCM(), jwa.A256GCM(),
}

// NewDecryptionConfig returns a [DecryptionConfig] with the options applied to
// it. Without options it accepts each content encryption algorithm of this
// module, and each key management algorithm of it other than RSA1_5.
//
// RSA1_5 is available and is not a default. [jwa.RSAESPKCS1v15] gives the cause.
// A recipient that must read such a token names it in
// [WithKeyManagementAlgorithms] with the other algorithms that the recipient
// accepts.
func NewDecryptionConfig(options ...func(*DecryptionConfig)) DecryptionConfig {
	config := DecryptionConfig{
		VerificationConfig: NewVerificationConfig(),
		keyManagement:      slices.Clone(defaultKeyManagementAlgorithms),
		contentEncryption:  slices.Clone(defaultContentEncryptionAlgorithms),
	}

	for _, option := range options {
		option(&config)
	}

	return config
}

// WithKeyManagementAlgorithms limits decryption to the given "alg" values.
func WithKeyManagementAlgorithms(algorithms ...jwa.Algorithm) func(*DecryptionConfig) {
	return func(config *DecryptionConfig) { config.keyManagement = algorithms }
}

// WithContentEncryptionAlgorithms limits decryption to the given "enc" values.
func WithContentEncryptionAlgorithms(algorithms ...jwa.Algorithm) func(*DecryptionConfig) {
	return func(config *DecryptionConfig) { config.contentEncryption = algorithms }
}

// WithVerification applies verification options to the signature of a Nested
// JWT.
func WithVerification(options ...func(*VerificationConfig)) func(*DecryptionConfig) {
	return func(config *DecryptionConfig) {
		for _, option := range options {
			option(&config.VerificationConfig)
		}
	}
}

// WithRequiredNestedToken rejects a JWE with a plaintext that is a claims set
// and not a signed JWT.
//
// For a recipient that must have encryption and a signature, this option closes
// a risk. Authenticated encryption shows that the message came from a party
// that holds the key. For a symmetric key that the two parties hold, this is each
// party with that key. Only the inner signature names which party it was.
func WithRequiredNestedToken() func(*DecryptionConfig) {
	return func(config *DecryptionConfig) { config.requireNestedToken = true }
}

// DefaultDecryptionConfig is a [DecryptionConfig] with the default values. It
// accepts each content encryption algorithm of this module, and each key
// management algorithm of it other than RSA1_5. See [NewDecryptionConfig].
//
// It is a package-level variable, thus a change to it changes each caller in the
// program. Use [NewDecryptionConfig] to make a different configuration.
var DefaultDecryptionConfig = NewDecryptionConfig()

// Decrypt reads an encrypted token and checks it. It gives nil when the token is
// satisfactory.
//
// Decrypt does the full operation. It decrypts the token, verifies the inner
// signature when the token is a Nested JWT, and checks the claims. It is one call
// and not two. A recipient that decrypted a nested token can ignore the
// verification, and it then accepts claims that no party signed. The type gives no
// indication of that error.
//
// Decrypt gets the keys from keys as [Token.Verify] does. One JWK Set holds the
// decryption key and, for a Nested JWT, the signature key of the inner token.
// Decrypt gets the keys again one time when the source is a [jwk.Refresher] and
// no key of the first set is suitable, for the decryption key and for the
// signature key together.
//
// Decrypt gives [ErrUnencrypted] for a token that is not encrypted, and
// [ErrForbiddenKeyManagement] for an "alg" or "enc" value that config does not
// accept.
func (token *Token) Decrypt(ctx context.Context, keys jwk.Source, config DecryptionConfig) error {
	token.authenticatedTypes = nil

	if err := token.encrypt(); err != nil {
		return err
	}

	if token.message == nil {
		return ErrUnencrypted
	}

	protectedHeader := token.message.ProtectedHeader
	if protectedHeader == nil {
		return fmt.Errorf("%w: no protected header", ErrMalformedToken)
	}

	if err := checkPermitted(config.keyManagement, protectedHeader.Algorithm); err != nil {
		return err
	}

	if err := checkPermitted(config.contentEncryption, protectedHeader.EncryptionAlgorithm); err != nil {
		return err
	}

	return withKeys(ctx, keys, func(keySet *jwk.KeySet) error {
		return token.decrypt(ctx, protectedHeader, keySet, config)
	})
}

func (token *Token) decrypt(
	ctx context.Context, protectedHeader *header.Header, keySet *jwk.KeySet, config DecryptionConfig,
) error {
	key, err := keySet.Key(
		jwk.Encryption,
		[]jwk.Operation{keyOperation(protectedHeader.Algorithm)},
		protectedHeader.Algorithm,
		protectedHeader.KeyID,
	)
	if err != nil {
		return err
	}

	plaintext, err := token.message.Decrypt(key.Material())
	if err != nil {
		return err
	}

	nested := isNested(protectedHeader.ContentType)

	if config.requireNestedToken && !nested {
		return fmt.Errorf("%w: the plaintext is not a Nested JWT", ErrUnsigned)
	}

	if nested {
		return token.adoptNested(ctx, string(plaintext), keySet, config)
	}

	if token.payload == nil {
		token.payload = new(payload)
	} else {
		*token.payload = payload{}
	}

	if err := json.Unmarshal(plaintext, token.payload); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}

	token.authenticatedTypes = []string{protectedHeader.Type}

	if err := token.checkClaims(ctx, config.VerificationConfig); err != nil {
		return err
	}

	token.verified = true

	return nil
}

func (token *Token) adoptNested(
	ctx context.Context, plaintext string, keySet *jwk.KeySet, config DecryptionConfig,
) error {
	inner, err := Unmarshal(plaintext)
	if err != nil {
		return fmt.Errorf("%w: nested token: %w", ErrMalformedToken, err)
	}

	if inner.message != nil {
		return fmt.Errorf("%w: nested token is itself encrypted", ErrMalformedToken)
	}

	token.payload = inner.payload
	token.signatures = inner.signatures

	return token.Verify(ctx, keySet, config.VerificationConfig)
}

func keyOperation(algorithm jwa.Algorithm) jwk.Operation {
	switch algorithm.(type) {
	case *jwa.Direct:
		return jwk.Decrypt

	case *jwa.ECDHESAlgorithm:
		return jwk.DeriveKey

	default:
		return jwk.UnwrapKey
	}
}

func checkPermitted(permitted []jwa.Algorithm, algorithm jwa.Algorithm) error {
	if algorithm == nil {
		return fmt.Errorf("%w: the protected header names no algorithm", ErrMalformedToken)
	}

	if !slices.Contains(permitted, algorithm) {
		return fmt.Errorf("%w: %v", ErrForbiddenKeyManagement, algorithm)
	}

	return nil
}
