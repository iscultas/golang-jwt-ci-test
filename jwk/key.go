// Package jwk supplies JSON Web Key, RFC 7517.
//
// A [Key] is one JWK. It holds key material from crypto/ecdsa, crypto/rsa,
// crypto/ed25519, crypto/ecdh, crypto/mldsa, or a []byte for a symmetric key.
// It also holds the parameters, for example "kid", "use" and "key_ops". A
// [KeySet] is a JWK Set.
//
// [NewKey] makes a Key from key material, with options, for example [WithID].
// Each option has a method that gives the parameter again, for example [Key.ID].
// Thus a caller can read the parameters of a key that it did not make.
// MarshalJSON and UnmarshalJSON change a Key into JSON and back again.
// [Key.Public] and [KeySet.Public] remove the secret half of a key, thus a
// caller can publish a JWK Set with no private material in it.
//
// The package also supplies the JWK Thumbprint and the JWK Thumbprint URI. See
// [Key.Thumbprint], [Key.ThumbprintURI] and [ParseThumbprintURI].
//
// A [Source] gives the keys that verification and decryption select from. A
// *[KeySet] is such a source, thus a caller with the keys in memory gives the set
// itself. [SourceFunc] makes a source from a function, for a caller that reads
// the keys from a file or a database. A source that also has the [Refresher]
// method gets the keys again when no key of its set is suitable.
//
// This package makes no request. It reads "x5u" and the "jku" parameter of a
// header as a URI and does not get the resource that the URI names. The
// [remote] package gets a JWK Set from an address that the caller gives, and it
// is a [Refresher].
//
// [remote]: https://pkg.go.dev/github.com/iscultas/jwt-go/jwk/remote
package jwk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"

	"github.com/iscultas/jwt-go/internal/base64url"
	"github.com/iscultas/jwt-go/internal/curve"
	"github.com/iscultas/jwt-go/internal/jsonerr"
	"github.com/iscultas/jwt-go/jwa"
)

// Type is the "kty" value of a key. It gives the family of the algorithm.
type Type string

// The registered key types.
const (
	EllipticCurve Type = "EC"
	RSA           Type = "RSA"
	OctetSequence Type = "oct"
	OctetKeyPair  Type = "OKP"
)

// AlgorithmKeyPair is the "AKP" key type.
//
// An AKP key holds the key of an algorithm that gives its own key format. The
// "alg" parameter is necessary for such a key, because that parameter states
// the format of the "pub" and "priv" octets. ML-DSA is the one algorithm for
// this key type, and it is the one algorithm that this package supplies for it.
// See [jwa.MLDSA44].
const AlgorithmKeyPair Type = "AKP"

// PublicKeyUse is the "use" value of a public key. It tells a recipient if the
// key is for signatures or for encryption.
type PublicKeyUse string

// The public key uses.
const (
	Signature  PublicKeyUse = "sig"
	Encryption PublicKeyUse = "enc"
)

// Operation is one value of the "key_ops" array. The array gives the operations
// that the key is for.
type Operation string

// The key operations.
const (
	Sign       Operation = "sign"
	Verify     Operation = "verify"
	Encrypt    Operation = "encrypt"
	Decrypt    Operation = "decrypt"
	WrapKey    Operation = "wrapKey"
	UnwrapKey  Operation = "unwrapKey"
	DeriveKey  Operation = "deriveKey"
	DeriveBits Operation = "deriveBits"
)

// Key is one JSON Web Key.
//
// A Key holds key material and the JWK parameters that give its properties. The material
// is an [*ecdsa.PublicKey], an [*rsa.PrivateKey], an [ed25519.PublicKey], an
// [*ecdh.PublicKey], an [*mldsa.PublicKey], a []byte, or one of the other types
// that [NewKey] accepts.
// [Key.Material] gives it back.
//
// A Key that a caller does not change is safe for use by more than one goroutine.
// The option functions change a Key, thus a caller must apply them before it
// makes the Key available to other goroutines.
//
// The zero Key has no material and an empty [Type]. MarshalJSON rejects such a
// Key with [ErrUnsupportedKeyType].
type Key struct {
	keyType      Type
	publicKeyUse PublicKeyUse
	operations   []Operation
	algorithm    jwa.Algorithm
	id           string

	x509URL                         *url.URL
	x509CertificateChain            []*x509.Certificate
	x509CertificateSHA1Thumbprint   string
	x509CertificateSHA256Thumbprint string

	material any
}

// ErrUnsupportedKeyType is the error for a key with material of a type that this
// package cannot write as a JWK.
//
// A Key that comes from a JSON object with a "kty" value that is not one of the
// four types above holds no material. Such a Key gives the same error, because
// no data can give its properties.
var ErrUnsupportedKeyType = errors.New("jwk: unsupported key type")

// NewKey returns a Key that holds material. It applies each option to the Key.
//
// NewKey finds the "kty" value from the type of material:
//
//   - [*ecdsa.PublicKey] or [*ecdsa.PrivateKey] gives "EC"
//   - [*rsa.PublicKey] or [*rsa.PrivateKey] gives "RSA"
//   - [ed25519.PublicKey] or [ed25519.PrivateKey] gives "OKP"
//   - an X25519 [*ecdh.PublicKey] or [*ecdh.PrivateKey] gives "OKP"
//   - [*mldsa.PublicKey] or [*mldsa.PrivateKey] gives "AKP"
//   - []byte gives "oct"
//
// An ML-DSA key also gets its "alg" value, which is [jwa.MLDSA44],
// [jwa.MLDSA65] or [jwa.MLDSA87]. That parameter is necessary for an "AKP" key,
// and the parameter set of the material states which of the three values is
// correct. NewKey applies each option after this, thus [WithAlgorithm] can
// still write a different value. MarshalJSON then rejects the key: see RFC 9964
// section 7.4.
//
// A crypto/ecdh key on a NIST curve gets an empty [Type]. Such a curve is an
// "EC" JWK, and this package uses [*ecdsa.PublicKey] for it. Thus MarshalJSON
// rejects the key by name and does not write a P-256 key with the incorrect
// "kty" value. The zero value of the two crypto/mldsa key types gets an empty
// Type for the same reason: it holds no parameter set, thus no "alg" value names
// it.
func NewKey(material any, options ...func(*Key)) *Key {
	var (
		keyType   Type
		algorithm jwa.Algorithm
	)

	switch material := material.(type) {
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		keyType = EllipticCurve
	case *rsa.PublicKey, *rsa.PrivateKey:
		keyType = RSA
	case ed25519.PublicKey, ed25519.PrivateKey:
		keyType = OctetKeyPair
	case *ecdh.PublicKey:
		if material.Curve() == ecdh.X25519() {
			keyType = OctetKeyPair
		}
	case *ecdh.PrivateKey:
		if material.Curve() == ecdh.X25519() {
			keyType = OctetKeyPair
		}
	case *mldsa.PublicKey, *mldsa.PrivateKey:
		if akp, ok := akpAlgorithm(material); ok {
			keyType, algorithm = AlgorithmKeyPair, akp
		}
	case []byte:
		keyType = OctetSequence
	}

	key := &Key{
		keyType:   keyType,
		algorithm: algorithm,
		material:  material,
	}

	for _, option := range options {
		option(key)
	}

	return key
}

// Material returns the key material that the Key holds. The type is one of the
// types that [NewKey] accepts. It is nil for a nil Key.
func (key *Key) Material() any {
	if key == nil {
		return nil
	}

	return key.material
}

// Type returns the "kty" value of the key.
//
// It is empty for a Key that [NewKey] made from material that this package cannot
// write. A caller must see this condition, because MarshalJSON rejects such a
// Key. It is better to tell the caller before it tries to publish the Key. Type
// also gives an empty value for a nil Key.
func (key *Key) Type() Type {
	if key == nil {
		return ""
	}

	return key.keyType
}

// IsPrivate reports whether the key holds secret material. Secret material is the
// private half of an asymmetric key, or a symmetric key, which is fully secret.
// IsPrivate gives false for a nil Key.
//
// A caller uses IsPrivate to apply the rules for a key in a public position.
// RFC 7518 section 4.6.1.1 makes the "epk" Header Parameter "contain only public
// key parameters". RFC 7517 section 4.1 gives the same limit for a JWK Set that a
// server publishes.
func (key *Key) IsPrivate() bool {
	if key == nil {
		return false
	}

	switch key.material.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey, *mldsa.PrivateKey:
		return true
	case ed25519.PublicKey:
		return false
	case []byte:
		return true
	}

	return false
}

// Public returns a Key with the public half of the material only. It keeps each
// other parameter with no change. It gives nil for a nil Key.
//
// Public also gives nil for a symmetric key, which has no public half. To
// return such a key with no change gives the secret as a publishable
// value.
//
// [KeySet.Public] uses this method to make a JWK Set for publication. This is
// necessary because MarshalJSON writes "d" and the RSA primes when the key has
// them.
func (key *Key) Public() *Key {
	if key == nil {
		return nil
	}

	publicKey := *key

	switch material := key.material.(type) {
	case *ecdsa.PrivateKey:
		publicKey.material = &material.PublicKey
	case *rsa.PrivateKey:
		publicKey.material = &material.PublicKey
	case ed25519.PrivateKey:
		publicKey.material = material.Public().(ed25519.PublicKey) //nolint:forcetypeassert // Public of an ed25519.PrivateKey returns an ed25519.PublicKey, by the contract of that method.
	case ed25519.PublicKey:
	case *ecdh.PrivateKey:
		publicKey.material = material.PublicKey()
	case *ecdh.PublicKey:
	case *mldsa.PrivateKey:
		if *material == (mldsa.PrivateKey{}) {
			return nil
		}

		publicKey.material = material.PublicKey()
	case *mldsa.PublicKey:
	case []byte:
		return nil
	}

	publicKey.x509CertificateChain = slices.Clone(key.x509CertificateChain)
	publicKey.operations = slices.Clone(key.operations)

	return &publicKey
}

// PublicKeyUse returns the "use" value of the key. It gives the zero value for
// a key with no such value, and for a nil Key.
func (key *Key) PublicKeyUse() PublicKeyUse {
	if key == nil {
		return ""
	}

	return key.publicKeyUse
}

// Operations returns the "key_ops" values of the key. It is nil for a key with
// no such value, and for a nil Key.
//
// A caller cannot change the key through the slice.
func (key *Key) Operations() []Operation {
	if key == nil {
		return nil
	}

	return slices.Clone(key.operations)
}

// Algorithm returns the "alg" value of the key. It is nil for a key with no
// such value, and for a nil Key.
//
// A key with this value names the algorithm to use with it. Thus [KeySet.Key] and
// [KeySet.Candidates] remove a key that gives a different algorithm.
func (key *Key) Algorithm() jwa.Algorithm {
	if key == nil {
		return nil
	}

	return key.algorithm
}

// ID returns the "kid" value of the key. It gives the zero value for a key with
// no such value, and for a nil Key.
//
// This value is a hint. Thus a caller uses it to find a key in a set, and not
// to trust the key that it finds.
func (key *Key) ID() string {
	if key == nil {
		return ""
	}

	return key.id
}

// X509URL returns the "x5u" value of the key. It is the URL of an X.509
// certificate chain. It is nil for a key with no such value, and for a nil Key.
//
// A caller cannot change the key through the URL: the result is a copy.
// [url.URL.Clone] makes a deep copy, thus the user information of the two URLs
// is also separate. This package does not read the certificate chain from the
// URL.
func (key *Key) X509URL() *url.URL {
	if key == nil || key.x509URL == nil {
		return nil
	}

	return key.x509URL.Clone()
}

// X509CertificateChain returns the "x5c" value of the key. The first
// certificate holds the public key of this JWK. It is nil for a key with no
// such value, and for a nil Key.
//
// A caller cannot change the key through the slice. A caller must not change a
// certificate in it, because the key uses that certificate. See
// [Key.CheckCertificateChain] for the rules that this package applies to a chain.
func (key *Key) X509CertificateChain() []*x509.Certificate {
	if key == nil {
		return nil
	}

	return slices.Clone(key.x509CertificateChain)
}

// X509CertificateSHA1Thumbprint returns the "x5t" value of the key. It is the
// base64url SHA-1 thumbprint of the first certificate in the chain. It gives
// the zero value for a key with no such value, and for a nil Key.
func (key *Key) X509CertificateSHA1Thumbprint() string {
	if key == nil {
		return ""
	}

	return key.x509CertificateSHA1Thumbprint
}

// X509CertificateSHA256Thumbprint returns the "x5t#S256" value of the key. It
// is the base64url SHA-256 thumbprint of the first certificate in the chain. It
// gives the zero value for a key with no such value, and for a nil Key.
func (key *Key) X509CertificateSHA256Thumbprint() string {
	if key == nil {
		return ""
	}

	return key.x509CertificateSHA256Thumbprint
}

// WithPublicKeyUse sets the "use" value of the key.
func WithPublicKeyUse(publicKeyUse PublicKeyUse) func(*Key) {
	return func(key *Key) {
		key.publicKeyUse = publicKeyUse
	}
}

// WithOperations sets the "key_ops" array of the key. The array must hold no
// duplicate value. See [ErrDuplicateKeyOperation].
func WithOperations(operations ...Operation) func(*Key) {
	return func(key *Key) {
		key.operations = operations
	}
}

// WithAlgorithm sets the "alg" value of the key.
func WithAlgorithm(algorithm jwa.Algorithm) func(*Key) {
	return func(key *Key) {
		key.algorithm = algorithm
	}
}

// WithID sets the "kid" value of the key.
func WithID(id string) func(*Key) {
	return func(key *Key) {
		key.id = id
	}
}

// WithX509URL sets the "x5u" value of the key. It is the URL of an X.509
// certificate chain.
//
// The key keeps a copy. A caller that changes its own URL after this option runs
// does not change the key, which [Key] gives as safe for use by more than one
// goroutine while no one changes it.
func WithX509URL(url *url.URL) func(*Key) {
	return func(key *Key) { key.x509URL = url.Clone() }
}

// WithX509CertificateChain sets the "x5c" value of the key. The first
// certificate in chain must hold the public key of this JWK.
func WithX509CertificateChain(chain []*x509.Certificate) func(*Key) {
	return func(key *Key) { key.x509CertificateChain = chain }
}

// WithX509CertificateSHA1Thumbprint sets the "x5t" value of the key. It is the
// base64url SHA-1 thumbprint of the first certificate in the chain.
func WithX509CertificateSHA1Thumbprint(thumbprint string) func(*Key) {
	return func(key *Key) { key.x509CertificateSHA1Thumbprint = thumbprint }
}

// WithX509CertificateSHA256Thumbprint sets the "x5t#S256" value of the key. It
// is the base64url SHA-256 thumbprint of the first certificate in the chain.
func WithX509CertificateSHA256Thumbprint(thumbprint string) func(*Key) {
	return func(key *Key) { key.x509CertificateSHA256Thumbprint = thumbprint }
}

// ErrDuplicateKeyOperation is the error for a key that names the same operation
// more than one time.
//
// The "key_ops" array holds no duplicate value. This package applies the rule
// when it encodes and when it decodes. Thus a serialization that it rejects on
// input is not a serialization that it writes.
var ErrDuplicateKeyOperation = errors.New("jwk: duplicate key operation")

// ErrInconsistentKeyUse is the error for a key that sets "use" and "key_ops"
// with values that do not agree. RFC 7517 section 4.3 prevents this: "if both are
// used, the information they convey MUST be consistent".
var ErrInconsistentKeyUse = errors.New("jwk: public key use contradicts key operations")

var operationUse = map[Operation]PublicKeyUse{
	Sign:       Signature,
	Verify:     Signature,
	Encrypt:    Encryption,
	Decrypt:    Encryption,
	WrapKey:    Encryption,
	UnwrapKey:  Encryption,
	DeriveKey:  Encryption,
	DeriveBits: Encryption,
}

func checkOperations(publicKeyUse PublicKeyUse, operations []Operation) error {
	comparableUse := publicKeyUse == Signature || publicKeyUse == Encryption

	seen := make(map[Operation]struct{}, len(operations))

	for _, operation := range operations {
		if _, duplicate := seen[operation]; duplicate {
			return fmt.Errorf("%w: %s", ErrDuplicateKeyOperation, operation)
		}

		seen[operation] = struct{}{}

		impliedUse, defined := operationUse[operation]
		if !comparableUse || !defined {
			continue
		}

		if impliedUse != publicKeyUse {
			return fmt.Errorf(
				"%w: %s implies a use of %q, key declares %q",
				ErrInconsistentKeyUse, operation, impliedUse, publicKeyUse,
			)
		}
	}

	return nil
}

func (key *Key) suitable(publicKeyUse PublicKeyUse, operations []Operation, algorithm jwa.Algorithm, id string) bool {
	if key.material == nil {
		return false
	}

	if key.publicKeyUse != "" && key.publicKeyUse != publicKeyUse {
		return false
	}

	for _, operation := range operations {
		if len(key.operations) > 0 && !slices.Contains(key.operations, operation) {
			return false
		}
	}

	if key.algorithm != nil && algorithm != nil && key.algorithm != algorithm {
		return false
	}

	if key.id != "" && id != "" && key.id != id {
		return false
	}

	return true
}

func (key *Key) weight(publicKeyUse PublicKeyUse, operations []Operation, algorithm jwa.Algorithm, id string) uint16 {
	var weight uint16

	if key.publicKeyUse == publicKeyUse {
		weight += 16
	}

	for _, operation := range operations {
		if slices.Contains(key.operations, operation) {
			weight += 8
		}
	}

	if key.algorithm != nil && key.algorithm == algorithm {
		weight += 64
	}

	if key.id != "" && key.id == id {
		weight += 128
	}

	return weight
}

type rawKey struct {
	Type         Type         `json:"kty,omitempty"`
	PublicKeyUse PublicKeyUse `json:"use,omitempty"`
	Operations   []Operation  `json:"key_ops,omitempty"`
	Algorithm    string       `json:"alg,omitempty"`
	ID           string       `json:"kid,omitempty"`

	X509Url                         string   `json:"x5u,omitempty"`
	X509CertificateChain            []string `json:"x5c,omitempty"`
	X509CertificateSha1Thumbprint   string   `json:"x5t,omitempty"`
	X509CertificateSha256Thumbprint string   `json:"x5t#S256,omitempty"`

	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`

	D string `json:"d,omitempty"`

	N  string `json:"n,omitempty"`
	E  string `json:"e,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	Dp string `json:"dp,omitempty"`
	Dq string `json:"dq,omitempty"`
	Qi string `json:"qi,omitempty"`
	// Held as raw JSON rather than as strings. Each element is an object, so a
	// conformant document would not decode into []string at all, and the type
	// error would obscure the real reason this package declines the key.
	Oth []jsontext.Value `json:"oth,omitempty"`

	K string `json:"k,omitempty"`

	// The AKP parameters. "pub" holds the public information class and "priv"
	// holds the private one. The "alg" member above states the format of the two,
	// thus neither one can be read without it.
	Pub  string `json:"pub,omitempty"`
	Priv string `json:"priv,omitempty"`
}

func bigIntToBase64(integer *big.Int) string {
	if integer == nil {
		return ""
	}

	return base64url.Encode(integer.Bytes())
}

func coordinateLength(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

func setEllipticCurveParameters(rawKey *rawKey, publicKey *ecdsa.PublicKey) error {
	curveName, x, y, err := ellipticCurveParameters(publicKey)
	if err != nil {
		return err
	}

	rawKey.Curve, rawKey.X, rawKey.Y = curveName, x, y

	return nil
}

func ellipticCurveParameters(publicKey *ecdsa.PublicKey) (string, string, string, error) {
	point, err := publicKey.Bytes()
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %w", ErrMalformedKey, err)
	}

	length := (len(point) - 1) / 2

	return publicKey.Curve.Params().Name,
		base64url.Encode(point[1 : 1+length]),
		base64url.Encode(point[1+length:]),
		nil
}

// MarshalJSON encodes the key as the JSON object.
//
// MarshalJSON writes the private parameters when the key holds them. These are
// "d" for an elliptic curve or OKP key, "priv" for an AKP key, and "d", "p",
// "q", "dp", "dq" and "qi" for an RSA key. Use [Key.Public] to get a key for
// publication.
//
// MarshalJSON gives [ErrUnsupportedKeyType] for a key with material that this
// package cannot write, and [ErrMultiPrimeKey] for an RSA key with more than two
// primes. It gives [ErrMalformedKey] for an AKP key whose "alg" value does not
// name the parameter set of its own material.
func (key *Key) MarshalJSON() ([]byte, error) {
	if err := checkOperations(key.publicKeyUse, key.operations); err != nil {
		return nil, err
	}

	if err := key.checkCertificates(); err != nil {
		return nil, err
	}

	rawKey := &rawKey{
		Type:         key.keyType,
		PublicKeyUse: key.publicKeyUse,
		Operations:   key.operations,
		ID:           key.id,

		X509CertificateSha1Thumbprint:   key.x509CertificateSHA1Thumbprint,
		X509CertificateSha256Thumbprint: key.x509CertificateSHA256Thumbprint,
	}

	if key.algorithm != nil {
		rawKey.Algorithm = key.algorithm.String()
	}

	if key.x509URL != nil {
		rawKey.X509Url = key.x509URL.String()
	}

	for _, certificate := range key.x509CertificateChain {
		rawKey.X509CertificateChain = append(rawKey.X509CertificateChain, base64.StdEncoding.EncodeToString(certificate.Raw))
	}

	switch key := key.material.(type) {
	case *ecdsa.PublicKey:
		if err := setEllipticCurveParameters(rawKey, key); err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		if err := setEllipticCurveParameters(rawKey, &key.PublicKey); err != nil {
			return nil, err
		}

		scalar, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedKey, err)
		}
		rawKey.D = base64url.Encode(scalar)
	case *rsa.PublicKey:
		rawKey.N = bigIntToBase64(key.N)
		rawKey.E = bigIntToBase64(big.NewInt(int64(key.E)))
	case *rsa.PrivateKey:
		rawKey.N = bigIntToBase64(key.N)
		rawKey.E = bigIntToBase64(big.NewInt(int64(key.E)))

		rawKey.D = bigIntToBase64(key.D)

		rawKey.P = bigIntToBase64(key.Primes[0])
		rawKey.Q = bigIntToBase64(key.Primes[1])

		if len(key.Primes) > 2 {
			return nil, fmt.Errorf("%w: got %d primes", ErrMultiPrimeKey, len(key.Primes))
		}

		rawKey.Dp = bigIntToBase64(key.Precomputed.Dp)
		rawKey.Dq = bigIntToBase64(key.Precomputed.Dq)
		rawKey.Qi = bigIntToBase64(key.Precomputed.Qinv)

	case ed25519.PublicKey:
		rawKey.Curve = Ed25519
		rawKey.X = base64url.Encode(key)
	case ed25519.PrivateKey:
		rawKey.Curve = Ed25519
		rawKey.X = base64url.Encode(key.Public().(ed25519.PublicKey)) //nolint:forcetypeassert // Public of an ed25519.PrivateKey returns an ed25519.PublicKey, by the contract of that method.

		rawKey.D = base64url.Encode(key.Seed())

	case *ecdh.PublicKey:
		if key.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: %s is an EC key; use *ecdsa.PublicKey", ErrUnsupportedKeyType, curve.Name(key.Curve()))
		}

		rawKey.Curve = X25519
		rawKey.X = base64url.Encode(key.Bytes())
	case *ecdh.PrivateKey:
		if key.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf(
				"%w: %s is an EC key; use *ecdsa.PrivateKey", ErrUnsupportedKeyType, curve.Name(key.Curve()),
			)
		}

		rawKey.Curve = X25519
		rawKey.X = base64url.Encode(key.PublicKey().Bytes())
		rawKey.D = base64url.Encode(key.Bytes())

	case *mldsa.PublicKey:
		if err := setAKPParameters(rawKey, key); err != nil {
			return nil, err
		}
	case *mldsa.PrivateKey:
		if err := setAKPParameters(rawKey, key); err != nil {
			return nil, err
		}

		rawKey.Priv = base64url.Encode(key.Bytes())

	case []byte:
		rawKey.K = base64url.Encode(key)

	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key)
	}

	return json.Marshal(rawKey)
}

func base64ToBigInt(s string) (*big.Int, error) {
	bytes, err := base64url.Decode(s)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(bytes), nil
}

var curves = []elliptic.Curve{
	elliptic.P256(),
	elliptic.P384(),
	elliptic.P521(),
}

// ErrUnsupportedCurve is the error for a key that names an elliptic curve which
// this package does not supply.
var ErrUnsupportedCurve = errors.New("jwk: unsupported curve")

// ErrMalformedKey is the error for a key that has each necessary parameter of its
// type, but with parameter values that cannot make a key.
var ErrMalformedKey = errors.New("jwk: malformed key")

// ErrMultiPrimeKey is the error for an RSA private key with more than two prime
// factors.
//
// The additional primes are in the "oth" parameter. A consumer that does not
// supply them can reject the key, and this package rejects it.
//
// The error occurs in the two directions. This package cannot read the object
// representation that the RFC gives for those elements, and it cannot write
// that representation.
var ErrMultiPrimeKey = errors.New("jwk: RSA key with more than two primes")

// MissingRequiredParameterError is the error for a key that does not have a
// parameter which its "kty" value makes necessary. The Parameter field names the
// missing member.
//
// That field is the cause of this type, and of the sentinel error that it is
// not. A producer that wrote an incomplete key must know which member is
// absent, and to read a name out of the message of an error is not an
// interface that this package can keep.
type MissingRequiredParameterError struct {
	// Parameter is the name of the JWK member that the key does not have. It is
	// the JWK member name, for example "crv", "x" or "n", and not the name of a
	// field of this package.
	Parameter string
}

// Error returns a message that names the missing parameter.
func (missing MissingRequiredParameterError) Error() string {
	return "jwk: missing required parameter: " + missing.Parameter
}

func decodeEllipticCurveParameter(encoded string, buffer []byte) error {
	decoded, err := base64url.Decode(encoded)
	if err != nil {
		return err
	}

	if len(decoded) > len(buffer) {
		return fmt.Errorf(
			"%w: parameter of %d octets, wider than the %d the curve allows", ErrMalformedKey, len(decoded), len(buffer),
		)
	}

	copy(buffer[len(buffer)-len(decoded):], decoded)

	return nil
}

func (key *Key) parseElipticCurve(rawKey *rawKey) error {
	if rawKey.Curve == "" {
		return &MissingRequiredParameterError{"crv"}
	}

	curveIndex := slices.IndexFunc(curves, func(curve elliptic.Curve) bool { return curve.Params().Name == rawKey.Curve })
	if curveIndex == -1 {
		return fmt.Errorf("%w: %s", ErrUnsupportedCurve, rawKey.Curve)
	}

	curve := curves[curveIndex]
	length := coordinateLength(curve)

	if rawKey.X == "" {
		return &MissingRequiredParameterError{"x"}
	}

	if rawKey.Y == "" {
		return &MissingRequiredParameterError{"y"}
	}

	point := make([]byte, 1+length*2)
	point[0] = 4

	if err := decodeEllipticCurveParameter(rawKey.X, point[1:1+length]); err != nil {
		return err
	}

	if err := decodeEllipticCurveParameter(rawKey.Y, point[1+length:]); err != nil {
		return err
	}

	publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedKey, err)
	}

	if rawKey.D == "" {
		key.material = publicKey

		return nil
	}

	scalar := make([]byte, length)
	if err := decodeEllipticCurveParameter(rawKey.D, scalar); err != nil {
		return err
	}

	privateKey, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedKey, err)
	}

	if !privateKey.PublicKey.Equal(publicKey) {
		return fmt.Errorf("%w: d does not match x and y", ErrMalformedKey)
	}

	key.material = privateKey

	return nil
}

// The OKP subtypes that this package supplies. Ed25519 is for signatures.
// X25519 is for key agreement. The names are "crv" values and not
// elliptic.Curve values, because the two curves have no representation in
// crypto/elliptic.
//
// The OKP subtypes also include Ed448 and X448. This package supplies no part
// of them, and it cannot supply them without a dependency that is not in the
// standard library. That library has no crypto/ed448, and its crypto/ecdh gives
// X25519 as its only curve that is not a NIST curve. This comment records the
// cause, thus a reader sees a limit and not an error.
const (
	Ed25519 = curve.Ed25519
	X25519  = curve.X25519
)

func (key *Key) parseX25519(rawKey *rawKey, publicKey []byte) error {
	remoteKey, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("%w: x: %w", ErrMalformedKey, err)
	}

	if rawKey.D == "" {
		key.material = remoteKey

		return nil
	}

	scalar, err := base64url.Decode(rawKey.D)
	if err != nil {
		return err
	}

	privateKey, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return fmt.Errorf("%w: d: %w", ErrMalformedKey, err)
	}

	if !privateKey.PublicKey().Equal(remoteKey) {
		return fmt.Errorf("%w: d does not correspond to x", ErrMalformedKey)
	}

	key.material = privateKey

	return nil
}

func (key *Key) parseOctetKeyPair(rawKey *rawKey) error {
	if rawKey.Curve == "" {
		return &MissingRequiredParameterError{"crv"}
	}

	if rawKey.Curve != Ed25519 && rawKey.Curve != X25519 {
		return fmt.Errorf("%w: %s", ErrUnsupportedCurve, rawKey.Curve)
	}

	if rawKey.X == "" {
		return &MissingRequiredParameterError{"x"}
	}

	publicKey, err := base64url.Decode(rawKey.X)
	if err != nil {
		return err
	}

	if rawKey.Curve == X25519 {
		return key.parseX25519(rawKey, publicKey)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"%w: x of %d octets, want %d", ErrMalformedKey, len(publicKey), ed25519.PublicKeySize,
		)
	}

	if rawKey.D == "" {
		key.material = ed25519.PublicKey(publicKey)

		return nil
	}

	seed, err := base64url.Decode(rawKey.D)
	if err != nil {
		return err
	}

	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%w: d of %d octets, want %d", ErrMalformedKey, len(seed), ed25519.SeedSize)
	}

	privateKey := ed25519.NewKeyFromSeed(seed)

	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) { //nolint:forcetypeassert // Public of an ed25519.PrivateKey returns an ed25519.PublicKey, by the contract of that method.
		return fmt.Errorf("%w: d does not correspond to x", ErrMalformedKey)
	}

	key.material = privateKey

	return nil
}

var mldsaAlgorithms = map[mldsa.Parameters]jwa.Algorithm{
	mldsa.MLDSA44(): jwa.MLDSA44(),
	mldsa.MLDSA65(): jwa.MLDSA65(),
	mldsa.MLDSA87(): jwa.MLDSA87(),
}

var mldsaParameters = func() map[jwa.Algorithm]mldsa.Parameters {
	parameters := make(map[jwa.Algorithm]mldsa.Parameters, len(mldsaAlgorithms))
	for set, algorithm := range mldsaAlgorithms {
		parameters[algorithm] = set
	}

	return parameters
}()

func mldsaPublicKey(material any) (*mldsa.PublicKey, bool) {
	switch material := material.(type) {
	case *mldsa.PublicKey:
		if *material == (mldsa.PublicKey{}) {
			return nil, false
		}

		return material, true
	case *mldsa.PrivateKey:
		if *material == (mldsa.PrivateKey{}) {
			return nil, false
		}

		return material.PublicKey(), true
	}

	return nil, false
}

func akpAlgorithm(material any) (jwa.Algorithm, bool) {
	publicKey, ok := mldsaPublicKey(material)
	if !ok {
		return nil, false
	}

	algorithm, ok := mldsaAlgorithms[publicKey.Parameters()]

	return algorithm, ok
}

func setAKPParameters(rawKey *rawKey, material any) error {
	publicKey, ok := mldsaPublicKey(material)
	if !ok {
		return fmt.Errorf("%w: %T holds no parameter set", ErrUnsupportedKeyType, material)
	}

	algorithm := mldsaAlgorithms[publicKey.Parameters()]

	if rawKey.Algorithm != "" && rawKey.Algorithm != algorithm.String() {
		return fmt.Errorf(
			"%w: alg is %q, but the key is %s", ErrMalformedKey, rawKey.Algorithm, algorithm,
		)
	}

	rawKey.Algorithm = algorithm.String()
	rawKey.Pub = base64url.Encode(publicKey.Bytes())

	return nil
}

func (key *Key) parseAKP(rawKey *rawKey) error {
	if rawKey.Algorithm == "" {
		return &MissingRequiredParameterError{"alg"}
	}

	parameters, ok := mldsaParameters[key.algorithm]
	if !ok {
		return fmt.Errorf(
			"%w: %s is not an AKP algorithm", jwa.ErrUnsupportedAlgorithm, rawKey.Algorithm,
		)
	}

	if rawKey.Pub == "" {
		return &MissingRequiredParameterError{"pub"}
	}

	encodedPublicKey, err := base64url.Decode(rawKey.Pub)
	if err != nil {
		return err
	}

	if size := parameters.PublicKeySize(); len(encodedPublicKey) != size {
		return fmt.Errorf("%w: pub of %d octets, want %d", ErrMalformedKey, len(encodedPublicKey), size)
	}

	publicKey, err := mldsa.NewPublicKey(parameters, encodedPublicKey)
	if err != nil {
		return fmt.Errorf("%w: pub: %w", ErrMalformedKey, err)
	}

	if rawKey.Priv == "" {
		key.material = publicKey

		return nil
	}

	seed, err := base64url.Decode(rawKey.Priv)
	if err != nil {
		return err
	}

	if len(seed) != mldsa.PrivateKeySize {
		return fmt.Errorf("%w: priv of %d octets, want %d", ErrMalformedKey, len(seed), mldsa.PrivateKeySize)
	}

	privateKey, err := mldsa.NewPrivateKey(parameters, seed)
	if err != nil {
		return fmt.Errorf("%w: priv: %w", ErrMalformedKey, err)
	}

	if !privateKey.PublicKey().Equal(publicKey) {
		return fmt.Errorf("%w: priv does not correspond to pub", ErrMalformedKey)
	}

	key.material = privateKey

	return nil
}

func parseRSAPrivateKey(rawKey *rawKey, publicKey rsa.PublicKey) (*rsa.PrivateKey, error) {
	d, err := base64ToBigInt(rawKey.D)
	if err != nil {
		return nil, err
	}

	if len(rawKey.Oth) != 0 {
		return nil, fmt.Errorf("%w: got %d beyond the first two", ErrMultiPrimeKey, len(rawKey.Oth))
	}

	var primes []*big.Int
	for _, rawPrime := range []string{rawKey.P, rawKey.Q} {
		if prime, err := base64ToBigInt(rawPrime); err == nil {
			primes = append(primes, prime)
		} else {
			return nil, err
		}
	}

	dp, err := base64ToBigInt(rawKey.Dp)
	if err != nil {
		return nil, err
	}

	dq, err := base64ToBigInt(rawKey.Dq)
	if err != nil {
		return nil, err
	}

	qi, err := base64ToBigInt(rawKey.Qi)
	if err != nil {
		return nil, err
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: publicKey,
		D:         d,
		Primes:    primes,
		Precomputed: rsa.PrecomputedValues{
			Dp:   dp,
			Dq:   dq,
			Qinv: qi,
		},
	}
	privateKey.Precompute()

	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedKey, err)
	}

	return privateKey, nil
}

const maxExponent = 1<<31 - 1

func (key *Key) parseRSA(rawKey *rawKey) error {
	if rawKey.N == "" {
		return &MissingRequiredParameterError{"n"}
	}
	n, err := base64ToBigInt(rawKey.N)
	if err != nil {
		return err
	}

	if rawKey.E == "" {
		return &MissingRequiredParameterError{"e"}
	}
	e, err := base64ToBigInt(rawKey.E)
	if err != nil {
		return err
	}

	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > maxExponent {
		return fmt.Errorf("%w: e of %s out of range", ErrMalformedKey, e)
	}

	publicKey := rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	if rawKey.D != "" && rawKey.P != "" && rawKey.Q != "" {
		privateKey, err := parseRSAPrivateKey(rawKey, publicKey)
		if err != nil {
			return err
		}

		key.material = privateKey
	} else {
		key.material = &publicKey
	}

	return nil
}

func (key *Key) parseOctetSequence(rawKey *rawKey) error {
	if rawKey.K == "" {
		return &MissingRequiredParameterError{"k"}
	}

	material, err := base64url.Decode(rawKey.K)
	if err == nil {
		key.material = material
	}

	return err
}

// UnmarshalJSON decodes the JSON object into the key.
//
// UnmarshalJSON parses the key material for a "kty" value of "EC", "RSA", "oct"
// or "OKP". For a different "kty" value the Key gets each other parameter but no
// material, and [Key.Material] then gives nil.
//
// UnmarshalJSON checks the X.509 parameters last. The parameters give the properties of the key
// material, thus a reader has no data to compare them with before this package
// reads that material.
//
// UnmarshalJSON rejects a JWK that names one member two times, and gives
// [jsontext.ErrDuplicateName]. A parser can reject such a document or read the
// last occurrence of the member. This package rejects: a key whose "k" or "n"
// reads differently to two readers of one document is not one key.
func (key *Key) UnmarshalJSON(data []byte) error {
	rawKey := new(rawKey)

	var err error

	if err = json.Unmarshal(data, rawKey); err != nil {
		return jsonerr.KeepDuplicateName(err)
	}

	key.keyType = rawKey.Type
	key.publicKeyUse = rawKey.PublicKeyUse
	key.operations = rawKey.Operations

	if err := checkOperations(key.publicKeyUse, key.operations); err != nil {
		return err
	}

	if rawKey.Algorithm != "" {
		algorithm, ok := jwa.ByName(rawKey.Algorithm)
		if !ok {
			return jwa.UnsupportedAlgorithm(rawKey.Algorithm)
		}

		key.algorithm = algorithm
	}

	key.id = rawKey.ID

	if rawKey.X509Url != "" {
		if x509URL, err := url.Parse(rawKey.X509Url); err == nil {
			key.x509URL = x509URL
		} else {
			return err
		}
	}

	for _, base64EncodedCertificate := range rawKey.X509CertificateChain {
		derEncodedCertificate, err := base64url.DecodeStandard(base64EncodedCertificate)
		if err != nil {
			return err
		}

		certificate, err := x509.ParseCertificate(derEncodedCertificate)
		if err != nil {
			return err
		}

		key.x509CertificateChain = append(key.x509CertificateChain, certificate)
	}

	key.x509CertificateSHA1Thumbprint = rawKey.X509CertificateSha1Thumbprint
	key.x509CertificateSHA256Thumbprint = rawKey.X509CertificateSha256Thumbprint

	switch rawKey.Type {
	case EllipticCurve:
		err = key.parseElipticCurve(rawKey)
	case RSA:
		err = key.parseRSA(rawKey)
	case OctetSequence:
		err = key.parseOctetSequence(rawKey)
	case OctetKeyPair:
		err = key.parseOctetKeyPair(rawKey)
	case AlgorithmKeyPair:
		err = key.parseAKP(rawKey)
	}

	if err != nil {
		return err
	}

	return key.checkCertificates()
}

// KeySet is a JWK Set. The Keys field holds the keys of the set.
//
// The zero KeySet holds no keys, and a caller can use it. A KeySet that a caller does
// not change is safe for use by more than one goroutine.
type KeySet struct {
	Keys []*Key `json:"keys"`
}

// NewKeySet returns a [KeySet] that holds keys.
func NewKeySet(keys ...*Key) *KeySet {
	return &KeySet{Keys: keys}
}

// MarshalJSON encodes the set as the JSON object.
//
// It keeps "keys" as an array for an empty set. RFC 7517 section 5 makes the
// value of that member "an array of JWKs".
//
// The empty slice is here and not left to the encoder. encoding/json/v2 writes
// [] for a nil slice, thus the two agree today, but the shape of this member is
// a rule of the RFC and not a default of an encoder.
func (keySet *KeySet) MarshalJSON() ([]byte, error) {
	keys := keySet.Keys
	if keys == nil {
		keys = []*Key{}
	}

	return json.Marshal(struct {
		Keys []*Key `json:"keys"`
	}{keys})
}

type rawKeySet struct {
	Keys []jsontext.Value `json:"keys"`
}

// UnmarshalJSON decodes a JWK Set and removes the keys in it that this package
// cannot use. RFC 7517 section 5 makes this the correct behavior:
// "Implementations SHOULD ignore JWKs within a JWK Set that use "kty" (key type)
// values that are not understood by them, that are missing required members, or
// for which values are out of the supported ranges."
//
// A server publishes one JWK Set for each consumer of it. Thus the set regularly
// holds a key type, a curve or an algorithm that one consumer does not supply. To
// reject the full document because of one such key keeps the other keys from
// the consumer. That is the failure that the section prevents.
//
// A key that names a "kty" value which this package does not supply parses with
// no error, but it holds no material. UnmarshalJSON removes it on that condition
// and not on an error. [KeySet.Key] also does not select such a key, because
// [Key.suitable] rejects a key with no material. Thus the set holds only
// keys that a caller can select.
//
// A document that names one member of the set two times is a different
// condition. UnmarshalJSON rejects it and gives [jsontext.ErrDuplicateName]. A
// parser can do this. A set that gives "keys" two times publishes one array and
// hides another.
func (keySet *KeySet) UnmarshalJSON(data []byte) error {
	rawKeySet := new(rawKeySet)
	if err := json.Unmarshal(data, rawKeySet); err != nil {
		return jsonerr.KeepDuplicateName(err)
	}

	keySet.Keys = make([]*Key, 0, len(rawKeySet.Keys))

	for _, rawKey := range rawKeySet.Keys {
		key := new(Key)

		if err := key.UnmarshalJSON(rawKey); err != nil || key.material == nil {
			continue
		}

		keySet.Keys = append(keySet.Keys, key)
	}

	return nil
}

// Public returns the set with the public half of each key only. It gives nil
// for a nil KeySet.
//
// Public removes a symmetric key and does not keep it, because [Key.Public] has
// no public half to give for such a key. To publish the secret is not the
// function of a caller that assembles a JWK Set.
func (keySet *KeySet) Public() *KeySet {
	if keySet == nil {
		return nil
	}

	keys := make([]*Key, 0, len(keySet.Keys))

	for _, key := range keySet.Keys {
		if publicKey := key.Public(); publicKey != nil {
			keys = append(keys, publicKey)
		}
	}

	return &KeySet{Keys: keys}
}

// ErrNoSuitableKey is the error from [KeySet.Key] when no key of the set is
// available for the given function.
var ErrNoSuitableKey = errors.New("jwk: no suitable key")

// Key returns the key of the set that is the best match for the given function.
//
// Key removes a key with a "use", "key_ops", "alg" or "kid" value that does not
// agree with the request. It does not rank such a key. Thus a caller does not
// use a key for a function that its publisher rejected.
//
// Key gives [ErrNoSuitableKey] if a caller can use no key of the set.
//
// A caller that verifies a signature must use [KeySet.Candidates]. The rank shows
// which key is the best match, but a JWK Set regularly holds some keys with the
// same rank.
func (keySet *KeySet) Key(
	publicKeyUse PublicKeyUse, operations []Operation, algorithm jwa.Algorithm, id string,
) (*Key, error) {
	if keySet == nil {
		return nil, ErrNoSuitableKey
	}

	var (
		best   *Key
		weight uint16
	)

	for _, key := range keySet.Keys {
		if key == nil || !key.suitable(publicKeyUse, operations, algorithm, id) {
			continue
		}

		if candidate := key.weight(publicKeyUse, operations, algorithm, id); best == nil || candidate > weight {
			best, weight = key, candidate
		}
	}

	if best == nil {
		return nil, ErrNoSuitableKey
	}

	return best, nil
}

// Candidates returns each key of the set that a caller can use for the given
// function, with the best match first. It gives nil for a nil KeySet.
//
// The rank is a preference, not an identification. A "kid" value makes the
// result one key when the two sides use such values. But that parameter is a
// hint. It is not necessary for a producer to send it.
//
// A JWK Set for all consumers together regularly holds some keys of one type.
// Each of those keys can be the key that signed a given token. RFC 9068 gives this condition directly: a resource
// server has "no way of knowing what key should be used to validate JWT access
// tokens in one", thus it must "accept signatures performed with any of
// the keys published".
//
// A verifier must thus try each key. To use the key with the best rank only
// rejects a token that a published key signed, if two keys have the same rank.
// Two keys of one type with no "kid" value always have the same rank.
//
// Candidates keeps the sequence of the set for keys of equal rank. A JWK Set
// usually gives the signature key of an issuer first, and this method keeps
// that sequence.
func (keySet *KeySet) Candidates(
	publicKeyUse PublicKeyUse, operations []Operation, algorithm jwa.Algorithm, id string,
) []*Key {
	if keySet == nil {
		return nil
	}

	candidates := make([]*Key, 0, len(keySet.Keys))

	for _, key := range keySet.Keys {
		if key == nil || !key.suitable(publicKeyUse, operations, algorithm, id) {
			continue
		}

		candidates = append(candidates, key)
	}

	if len(candidates) < 2 {
		return candidates
	}

	slices.SortStableFunc(candidates, func(a, b *Key) int {
		return int(b.weight(publicKeyUse, operations, algorithm, id)) -
			int(a.weight(publicKeyUse, operations, algorithm, id))
	})

	return candidates
}

// Get returns the set itself and no error. Thus a *KeySet is a [Source], and a
// caller that holds the keys in memory gives the set where a source is
// necessary.
//
// Get ignores the context, because it makes no request and does no other
// operation that a caller can stop. It gives a nil set for a nil KeySet, and
// [KeySet.Candidates] and [KeySet.Key] accept such a set.
//
// A KeySet is not a [Refresher]. The keys of a set in memory do not change, thus
// to get them a second time gives the same keys and makes no token verify that
// did not verify before.
func (keySet *KeySet) Get(context.Context) (*KeySet, error) { return keySet, nil }

// Source gives a JWK Set to a recipient that verifies or decrypts a token. A
// caller supplies a Source where this module needs keys, thus the keys can come
// from memory, from a file, from a database or from a server.
//
// This interface gives the source no data about the token. To select a key from
// the set is the function of [KeySet.Candidates] and [KeySet.Key], and it stays
// in this package. Thus an implementation cannot ignore the "use", "key_ops",
// "alg" or "kid" parameter of a key, and no value that the sender of a token
// controls reaches the code of the implementation.
//
// An implementation must be safe for use by more than one goroutine. A server
// verifies more than one token at the same time, and each verification gets the
// keys.
//
// The result is read and not changed. An implementation can give the same set to
// each caller, and the [remote] package does that.
//
// [remote]: https://pkg.go.dev/github.com/iscultas/jwt-go/jwk/remote
type Source interface {
	Get(ctx context.Context) (*KeySet, error)
}

// Refresher is a [Source] whose keys change. Verification calls Refresh when no
// key of the first set is suitable for the token, and it then makes one more
// attempt with the result.
//
// The method is not in [Source] because a set that does not change has nothing
// to get a second time. A caller that holds the keys in memory implements Source
// only, and verification then makes one attempt.
//
// Refresh must get the keys again and must not give a cached result. Get can
// give a cached set, and a recipient calls Refresh because that set has no key
// for the token.
//
// An implementation must limit how frequently it gets the keys. A token with an
// unknown "kid" value causes one call to this method, and that value comes from
// the sender. The [remote] package has a minimum interval for this reason, and
// it refuses a call inside that interval. Verification accepts that refusal and
// reports the error of the token.
//
// [remote]: https://pkg.go.dev/github.com/iscultas/jwt-go/jwk/remote
type Refresher interface {
	Source

	Refresh(ctx context.Context) (*KeySet, error)
}

// SourceFunc makes a [Source] from a function. Thus a caller that reads the keys
// from a file or a database gives a closure and does not write a type.
//
// A SourceFunc is not a [Refresher]. A caller whose keys change writes a type
// with the two methods of that interface.
type SourceFunc func(ctx context.Context) (*KeySet, error)

// Get calls the function.
func (source SourceFunc) Get(ctx context.Context) (*KeySet, error) { return source(ctx) }

var (
	_ Source = (*KeySet)(nil)
	_ Source = SourceFunc(nil)
)
