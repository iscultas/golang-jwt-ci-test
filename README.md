# jwt-go

JSON Object Signing and Encryption for Go: JSON Web Token, JSON Web Signature, JSON Web
Encryption, JSON Web Key and JSON Web Algorithms. The module has no dependency external to the
standard library.

[![Go Reference](https://pkg.go.dev/badge/github.com/iscultas/jwt-go.svg)](https://pkg.go.dev/github.com/iscultas/jwt-go)
[![CI](https://github.com/iscultas/jwt-go/actions/workflows/ci.yml/badge.svg)](https://github.com/iscultas/jwt-go/actions/workflows/ci.yml)
[![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8)](https://go.dev/dl/)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue)](UNLICENSE)

```go
token, err := jwt.NewToken(
	jwt.WithIssuer("https://issuer.example"),
	jwt.WithSubject("alice"),
	jwt.WithExpirationTime(&expiration),
	jwt.WithSignature(jwa.ES256(), key),
)
```

## Contents

- [Specifications](#specifications)
- [Requirements](#requirements)
- [Installation](#installation)
- [First token](#first-token)
- [Use](#use)
- [Algorithms](#algorithms)
- [Security considerations](#security-considerations)
- [Packages](#packages)
- [Benchmarks](#benchmarks)
- [Requirement coverage](#requirement-coverage)
- [Errors](#errors)
- [How to make a change](#how-to-make-a-change)
- [License](#license)

## Specifications

Each document in this table has a generated conformance suite in [conformance/](conformance),
and a coverage matrix in [rfc-conformance/](rfc-conformance).

| Document | Title | Coverage |
| --- | --- | --- |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature | [matrix](rfc-conformance/coverage-rfc7515.md) |
| [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) | JSON Web Encryption | [matrix](rfc-conformance/coverage-rfc7516.md) |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key | [matrix](rfc-conformance/coverage-rfc7517.md) |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms | [matrix](rfc-conformance/coverage-rfc7518.md) |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token | [matrix](rfc-conformance/coverage-rfc7519.md) |
| [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520) | Examples of protection with JOSE | [matrix](rfc-conformance/coverage-rfc7520.md) |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprint | [matrix](rfc-conformance/coverage-rfc7638.md) |
| [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) | JWS Unencoded Payload Option | [matrix](rfc-conformance/coverage-rfc7797.md) |
| [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) | Proof-of-Possession Key Semantics | [matrix](rfc-conformance/coverage-rfc7800.md) |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) | CFRG Elliptic Curve Algorithms | [matrix](rfc-conformance/coverage-rfc8037.md) |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) | JWT Best Current Practices | [matrix](rfc-conformance/coverage-rfc8725.md) |
| [RFC 9278](https://www.rfc-editor.org/rfc/rfc9278) | JWK Thumbprint URI | [matrix](rfc-conformance/coverage-rfc9278.md) |
| [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) | The `Ed25519` JWS algorithm | [matrix](rfc-conformance/coverage-rfc9864.md) |
| [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964) | ML-DSA for JOSE | [matrix](rfc-conformance/coverage-rfc9964.md) |
| [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) | Deterministic ECDSA | [matrix](rfc-conformance/coverage-rfc6979.md) |

## Requirements

Go 1.27. Two properties of the language and the library make that version necessary:

- The module encodes and decodes with `encoding/json/v2` and `encoding/json/jsontext`. Those
  packages refuse a duplicate member name, which the JOSE header makes necessary. No
  `GOEXPERIMENT` is necessary for them on Go 1.27.
- `Token.Claim` is a method with a type parameter.

## Installation

```bash
go get github.com/iscultas/jwt-go
```

## First token

This example signs a token with HS256 and then verifies it.

```go
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/iscultas/jwt-go"
	"github.com/iscultas/jwt-go/jwa"
	"github.com/iscultas/jwt-go/jwk"
)

func main() {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}

	key := jwk.NewKey(secret, jwk.WithID("2026-08"))

	expiration := time.Now().Add(time.Hour)

	token, err := jwt.NewToken(
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithSubject("alice"),
		jwt.WithAudience("https://api.example"),
		jwt.WithExpirationTime(&expiration),
		jwt.WithSignature(jwa.HS256(), key),
	)
	if err != nil {
		panic(err)
	}

	serialized, err := token.Marshal()
	if err != nil {
		panic(err)
	}

	received, err := jwt.Unmarshal(serialized)
	if err != nil {
		panic(err)
	}

	config := jwt.NewVerificationConfig(
		jwt.WithAlgorithms(jwa.HS256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
		jwt.WithExpectedAudience("https://api.example"),
	)

	if err := received.Verify(context.Background(), jwk.NewKeySet(key), config); err != nil {
		panic(err)
	}

	fmt.Println(received.Subject(), received.Verified()) // alice true
}
```

`Token.Verify` does the full operation. It makes each signature that `WithSignature` recorded,
it verifies the signatures against the key set, and it then checks the claims. It checks the
signatures first, thus no unauthenticated claim decides the outcome or reaches the caller in an
error message.

`Unmarshal` does no verification, because there is no key at that point. The accessors of the
token that it gives answer with the claims that came in, and those are the claims of the
producer of the octets and not facts. `Token.Verified` reports whether `Token.Verify` or
`Token.Decrypt` authenticated them.

## Use

### Claims

An option sets each of the seven registered claims. An accessor gives each of them again.
`WithPrivateClaim` sets a claim that is not in that set, and `Token.Claim` reads it with its
type.

```go
issuance := time.Now()
expiration := issuance.Add(15 * time.Minute)

token, err := jwt.NewToken(
	jwt.WithIssuer("https://issuer.example"),
	jwt.WithSubject("alice"),
	jwt.WithAudience("https://api.example", "https://other.example"),
	jwt.WithExpirationTime(&expiration),
	jwt.WithNotBefore(&issuance),
	jwt.WithIssuedAt(&issuance),
	jwt.WithID("7ce2b1a4"),
	jwt.WithPrivateClaim("scope", "read write"),
	jwt.WithSignature(jwa.HS256(), key),
)
if err != nil {
	panic(err)
}

scope, present, err := token.Claim[string]("scope")
if err != nil {
	panic(err)
}

fmt.Println(scope, present) // read write true

if err := token.RequireClaims("iss", "sub", "scope"); err != nil {
	panic(err)
}
```

The second result of `Token.Claim` tells if the claim is in the token. A claim that is not in
the token is not an error, because each registered claim is optional. A claim of a different
type gives `ErrMalformedClaim`, thus a caller reads an error and does not get a panic.
`Token.PrivateClaim` gives the same value as `any`.

`Token.RequireClaims` reports each name that the token does not hold, as one error that names
all of them.

### Verification

`NewVerificationConfig` gives what `Token.Verify` accepts. A configuration with no option
accepts each signature algorithm of this module other than `none`, and it applies one claim
check: the `typ` of the header that authenticated the token must be `JWT`, or absent. Each
other check is an option. The `keys` argument is a `jwk.Source`, and a `*jwk.KeySet` is one.
See [Key sources](#key-sources).

```go
config := jwt.NewVerificationConfig(
	jwt.WithAlgorithms(jwa.ES256(), jwa.EdDSA()),
	jwt.WithExpectedIssuer("https://issuer.example"),
	jwt.WithExpectedSubject("alice"),
	jwt.WithExpectedAudience("https://api.example", "https://api.internal.example"),
	jwt.WithExpectedType("at+jwt"),
	jwt.WithMaxAge(5*time.Minute),
	jwt.WithLeeway(30*time.Second),
)

if err := token.Verify(ctx, keys, config); err != nil {
	// ErrExpired, ErrNotYetValid, ErrUnexpectedIssuer, ErrUnexpectedSubject,
	// ErrUnexpectedAudience, ErrUnexpectedType, ErrTooOld, ErrIssuedInFuture,
	// ErrForbiddenAlgorithm, ErrUnverified, or the error of a rule.
	return err
}

fmt.Println(token.Verified()) // true
```

| Claim | Check | Default |
| --- | --- | --- |
| `iss` | `WithExpectedIssuer` | off |
| `sub` | `WithExpectedSubject` | off |
| `aud` | `WithExpectedAudience` | off |
| `exp` | applied when the claim is present | on |
| `nbf` | applied when the claim is present | on |
| `iat` | `WithMaxAge` | off |
| `jti` | `WithReplayCheck` | off |
| `typ` | `WithExpectedType`, `WithAnyType` | on |

`WithExpectedAudience` takes each name that this recipient answers to. A producer writes the one
name that it knows, thus a token that holds any of the names is a token for this recipient. A
second call replaces the names of the first, because the names are the full set and a call that
added to that set would make the check less strict with no indication.

`WithExpectedSubject` makes the `sub` claim necessary and equal to the name that it gives. The
`sub` claim is local to the issuer, unless the issuer gives it a global value. Thus a recipient
that reads more than one issuer gives `WithExpectedIssuer` also. To check the subject alone lets
one issuer name the subject of a different issuer.

`WithExpectedType` makes the `typ` of the protected header necessary and equal to the media type
that it gives. This is the explicit typing of RFC 8725 section 3.11, and `WithType` writes the
value that it reads. The compare is not case-sensitive, and it supplies `application/` for a
value with no `/`.

This module reads the `typ` of the header that authenticated the token, and of no other header.
A token can hold signatures that disagree on `typ`, and one signature of them verifies by
default. To read the header of a signature that no key accepted lets the producer of that
signature select the media type that the recipient sees.

The check applies with no option, and this is the one default that is not an algorithm. A
recipient that gives neither option rejects a media type other than `JWT`, thus a token of a
profile does not pass as a usual JWT. `WithAnyType` removes the check for a recipient that must
accept media types that it does not know first.

`WithMaxAge` makes the `iat` claim necessary and limits the age of the token. It is different
from the `exp` check: `exp` is the time that the producer selected, and `WithMaxAge` is the
limit of the recipient. An `iat` after the current time gives `ErrIssuedInFuture`, thus a
producer cannot select the limit of the recipient.

`WithReplayCheck` makes the `jti` claim necessary and gives it to an `IDStore`. The `jti` claim
is the value that prevents a replay, and the claim alone prevents none: a recipient must record
the identifiers that it accepted. This module supplies no `IDStore`,
because retention, concurrency and storage are properties of a deployment. The check runs after
each other check, thus a token that this module rejects for a different cause does not use up
its identifier.

```go
config := jwt.NewVerificationConfig(jwt.WithReplayCheck(store))

if err := token.Verify(ctx, keys, config); errors.Is(err, jwt.ErrReplayedToken) {
	// The store saw this jti before.
}
```

`WithLeeway` accepts clock skew in the checks of `exp`, `nbf` and `iat`. `WithClock` gives the
function that this module reads the current time from, and the default is `time.Now`.

```go
config := jwt.NewVerificationConfig(
	jwt.WithClock(func() time.Time { return time.Unix(3000, 0) }),
)

if err := token.Verify(ctx, keys, config); errors.Is(err, jwt.ErrExpired) {
	// The token expired before that time.
}
```

A test that must put the current time after the `exp` claim of a token gives `WithClock`, and
does not have to wait for that time to arrive. A rule reads the same clock with
`VerificationConfig.Now`, thus a rule and this module read one clock. This module reads that
clock one time for a verification, thus `exp` and `nbf` cannot answer to different times.

### Signatures

`WithSignature` records the algorithm and the key. This module makes the signature when a
caller marshals or verifies the token. Thus the options apply in any sequence, and a caller
can set a claim after it gave the signature.

```go
material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
	panic(err)
}

key := jwk.NewKey(material, jwk.WithID("2026-08"))

token, err := jwt.NewToken(
	jwt.WithSignature(
		jwa.ES256(), key,
		jws.WithProtectedHeader(header.WithKeyID(key.ID())),
	),
	jwt.WithType("at+jwt"),
	jwt.WithIssuer("https://issuer.example"),
)
if err != nil {
	panic(err)
}

for _, pending := range token.Pending() {
	fmt.Println(pending.Algorithm, pending.Key.ID()) // ES256 2026-08
}
```

`jws.WithProtectedHeader` puts a parameter in the JWS Protected Header, which the signature
includes in its input. `jws.WithHeader` puts one in the JWS Unprotected Header, which it does
not include.
The [header](header) package supplies the options for the JOSE header parameters: `WithKeyID`,
`WithJWK`, `WithJWKSetURL`, `WithX509URL`, `WithX509CertificateChain` and the two X.509
thumbprint options.

`WithType` sets the `typ` value of each protected header. It gives the explicit typing, which
lets a recipient tell a token of a profile apart from a usual JWT.

`Token.Pending` gives the signatures that the token will make, before it makes them.
`Token.Signatures` gives them after.

### Encryption

`WithEncryption` makes a JWE JWT, and `Token.Decrypt` reads one. The key management algorithm
gives protection to the Content Encryption Key, and the content encryption algorithm encrypts
the claims.

```go
material, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
	panic(err)
}

recipient := jwk.NewKey(
	material,
	jwk.WithPublicKeyUse(jwk.Encryption),
	jwk.WithOperations(jwk.DeriveKey),
)

token, err := jwt.NewToken(
	jwt.WithIssuer("https://issuer.example"),
	jwt.WithSubject("alice"),
	jwt.WithEncryption(jwa.ECDHESA256KW(), jwa.A256GCM(), recipient.Public()),
)
if err != nil {
	panic(err)
}

serialized, err := token.Marshal()
if err != nil {
	panic(err)
}

received, err := jwt.Unmarshal(serialized)
if err != nil {
	panic(err)
}

config := jwt.NewDecryptionConfig(
	jwt.WithKeyManagementAlgorithms(jwa.ECDHESA256KW()),
	jwt.WithContentEncryptionAlgorithms(jwa.A256GCM()),
)

if err := received.Decrypt(ctx, jwk.NewKeySet(recipient), config); err != nil {
	panic(err)
}

fmt.Println(received.Subject()) // alice
```

`jwt.Unmarshal` reads the two compact serializations. A count of parts tells the two apart: a
JWS has three parts and a JWE has five. A token with five parts stays in its encrypted
condition, and its claims are not available until `Token.Decrypt` supplies a key.

The [jwe](jwe) package supplies the JWE object independently of a JWT. `jwe.Message` encrypts
arbitrary content, and `Message.EncryptTo` encrypts to more than one recipient.

### Nested JWT

`WithSignature` with `WithEncryption` makes a Nested JWT. This module signs the claims and then
encrypts the JWS, and that sequence is necessary. A signature on a ciphertext shows only that
the signer saw the ciphertext. A signature below the encryption shows that the signer accepted
the claims.

```go
token, err := jwt.NewToken(
	jwt.WithIssuer("https://issuer.example"),
	jwt.WithSubject("alice"),
	jwt.WithSignature(jwa.ES256(), signingKey),
	jwt.WithEncryption(jwa.Dir(), jwa.A256GCM(), encryptionKey),
)
if err != nil {
	panic(err)
}

serialized, err := token.Marshal()
if err != nil {
	panic(err)
}

received, err := jwt.Unmarshal(serialized)
if err != nil {
	panic(err)
}

config := jwt.NewDecryptionConfig(
	jwt.WithRequiredNestedToken(),
	jwt.WithVerification(
		jwt.WithAlgorithms(jwa.ES256()),
		jwt.WithExpectedIssuer("https://issuer.example"),
	),
)

if err := received.Decrypt(
	ctx, jwk.NewKeySet(encryptionKey, signingKey.Public()), config,
); err != nil {
	panic(err)
}

fmt.Println(received.Subject()) // alice
```

`Token.Decrypt` decrypts the token, verifies the inner signature, and checks the claims. It is
one operation and not two, because a recipient that decrypted a nested token and then ignored the
verification accepts claims that no party signed.

`WithRequiredNestedToken` rejects a JWE with a plaintext that is a bare claims set. Authenticated
encryption shows that the message came from a party that holds the key. For a symmetric key
that two parties hold, that is each of the two parties. Only the inner signature names which
one it was.

### Keys

`jwk.NewKey` makes a key from material of `crypto/ecdsa`, `crypto/rsa`, `crypto/ed25519`,
`crypto/ecdh`, `crypto/mldsa`, or a `[]byte` for a symmetric key. An option sets each JWK
parameter, and a method gives it again.

```go
key := jwk.NewKey(
	material,
	jwk.WithPublicKeyUse(jwk.Signature),
	jwk.WithOperations(jwk.Sign, jwk.Verify),
	jwk.WithAlgorithm(jwa.ES256()),
	jwk.WithID("2026-08"),
)

fmt.Println(key.Type(), key.IsPrivate(), key.Public().IsPrivate()) // EC true false

thumbprint, err := key.ThumbprintID(crypto.SHA256)
if err != nil {
	panic(err)
}

uri, err := key.ThumbprintURI(crypto.SHA256)
if err != nil {
	panic(err)
}

fmt.Println(thumbprint) // the base64url SHA-256 thumbprint of this key
fmt.Println(uri)        // urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>

published, err := json.Marshal(jwk.NewKeySet(key).Public())
if err != nil {
	panic(err)
}

set := new(jwk.KeySet)
if err := json.Unmarshal(published, set); err != nil {
	panic(err)
}

candidate, err := set.Key(jwk.Signature, []jwk.Operation{jwk.Verify}, jwa.ES256(), "2026-08")
if err != nil {
	panic(err)
}

fmt.Println(candidate.ID()) // 2026-08
```

A `crypto/mldsa` key gets the `AKP` key type, and it also gets its `alg` value. That parameter
is necessary for an `AKP` key, because the format of `pub` and `priv` depends on it, and the
parameter set of the material states which of the three values is correct. It is the one key
type of this package for which `alg` is not a hint that a reader can drop.

`Key.Public` and `KeySet.Public` remove the secret half of a key. Thus a caller publishes a JWK
Set with no private material in it. `KeySet.Key` selects the most applicable key for a public
key use, a set of operations, an algorithm and an identifier, and `KeySet.Candidates` gives all
of them in sequence of suitability.

`Key.Thumbprint` gives the JWK Thumbprint. `Key.ThumbprintID` gives it as a base64url string,
and `Key.ThumbprintURI` gives the thumbprint URI, which `jwk.ParseThumbprintURI` reads again.

`Key.CheckCertificateChain` checks an `x5c` chain against the key, its use and its thumbprints.
The [jwk](jwk) package parses `x5u` and `jku` and does not get the resource. See
[Security considerations](#security-considerations).

### Key sources

`Token.Verify`, `Token.Decrypt` and `Token.VerifySignature` take a `jwk.Source`. It is one
method, and it gives the keys of the recipient.

```go
type Source interface {
	Get(ctx context.Context) (*jwk.KeySet, error)
}
```

A `*jwk.KeySet` is a `Source`, thus a caller that holds the keys in memory gives the set.

```go
err := token.Verify(ctx, jwk.NewKeySet(publicKey), config)
```

`jwk.SourceFunc` makes a source from a function, for a caller that reads the keys from a file or
a database.

```go
keys := jwk.SourceFunc(func(ctx context.Context) (*jwk.KeySet, error) {
	return store.Keys(ctx)
})
```

The source gives the whole set and learns nothing about the token. To select a key from the set
is the function of `KeySet.Candidates` and `KeySet.Key`, and it stays in this module. Thus an
implementation cannot ignore the `use`, `key_ops`, `alg` or `kid` parameter of a key, and no
value that the sender of a token controls reaches the code of that implementation. An
implementation must be safe for use by more than one goroutine.

A source whose keys change also has a `Refresh` method:

```go
type Refresher interface {
	Source

	Refresh(ctx context.Context) (*jwk.KeySet, error)
}
```

Verification calls `Refresh` when no key of the first set is suitable for the token, and it then
makes one more attempt. Thus a recipient accepts a token from an issuer that changed its keys,
and the recipient writes no loop of its own. A `*jwk.KeySet` is not a `Refresher`: the keys of a
set in memory do not change.

This module calls `Refresh` for `jwk.ErrNoSuitableKey` only. A signature that does not verify
under a key that the set holds gives `ErrUnverified`, and this module makes no second attempt for
it. Thus a sender with a token that no key signed cannot make a recipient get the keys again for
each such token. An issuer that changes the key material and keeps the `kid` value is the one
condition that this does not correct.

A refusal from `Refresh` does not replace the error of the token. The result holds the two
errors, thus `errors.Is` finds `jwk.ErrNoSuitableKey` and the message also names the refusal.

### Key sets over HTTPS

An issuer publishes its public keys as a JWK Set at an address. `jwk/remote` gets that document
and keeps the keys, thus a recipient that verifies many tokens makes few requests. A
`remote.Source` is a `jwk.Refresher`.

```go
keys, err := remote.NewSource(
	"https://issuer.example/.well-known/jwks.json",
	remote.WithRefreshInterval(15*time.Minute),
	remote.WithMinimumInterval(time.Minute),
)
if err != nil {
	panic(err)
}

err = token.Verify(ctx, keys, config)
```

That is the whole operation. Verification gets the keys, and it gets them again one time when
the issuer signs with a key that this recipient does not hold.

The address comes from the caller and never from a token. See
[Security considerations](#security-considerations).

`KeySet.Get` gives the keys that it holds until they reach the refresh interval. `KeySet.Refresh`
gets them again, for a token that names a key which the recipient does not hold. A refresh obeys
the minimum interval and gives `ErrTooSoon` inside it: a token names its own key, thus a token
that names a key of no one would otherwise make one request to the issuer for each token that
arrives. One request happens at a time, thus many tokens of one unknown key make one request.

A response above the limit of `WithResponseLimit` is not read, and one mebioctet is the default.

### JSON serialization

The compact serialization holds one signature. `Token.MarshalJSON` writes the JWS JSON
Serialization, which holds more than one. It writes the flattened serialization for one
signature, and the general serialization for more.

```go
token, err := jwt.NewToken(
	jwt.WithIssuer("https://issuer.example"),
	jwt.WithSignature(jwa.ES256(), firstKey),
	jwt.WithSignature(jwa.ES384(), secondKey),
)
if err != nil {
	panic(err)
}

if _, err := token.Marshal(); !errors.Is(err, jwt.ErrMultipleSignatures) {
	panic("want ErrMultipleSignatures")
}

serialized, err := json.Marshal(token)
if err != nil {
	panic(err)
}

received := new(jwt.Token)
if err := json.Unmarshal(serialized, received); err != nil {
	panic(err)
}

config := jwt.NewVerificationConfig(
	jwt.WithAlgorithms(jwa.ES256(), jwa.ES384()),
	jwt.WithAllSignatures(),
)

if err := received.Verify(
	ctx, jwk.NewKeySet(firstKey.Public(), secondKey.Public()), config,
); err != nil {
	panic(err)
}

fmt.Println(len(received.Signatures())) // 2
```

One signature that verifies is sufficient by default, because a recipient usually holds one key
of the keys of an issuer. `WithAllSignatures` makes each signature verify, for a caller that
holds the key of each signer and must check that each of them signed.

An encrypted token gets the JWE JSON Serialization.

### Profiles

A profile of the JWT, for example RFC 9068, adds rules to the mechanism. This module supplies
the two positions where a rule operates, and it gives no rule. A caller writes the rules of its
profile.

- A `Rule` operates after each signature verifies, and before the time, issuer and audience
  checks.
  Thus each claim that it reads is a claim that the signer made.
- An `IssuanceRule` operates one time, before this module makes any signature. Thus this module
  writes no token that a rule rejects, and it does not find the error after it wrote the token.

```go
// errMACAlgorithm rejects a shared-secret signature on an access token.
var errMACAlgorithm = errors.New("profile: an access token needs an asymmetric signature")

func issuanceRule(token *jwt.Token) error {
	for _, pending := range token.Pending() {
		if _, mac := pending.Algorithm.(*jwa.HMACSHA2); mac {
			return errMACAlgorithm
		}
	}

	return token.RequireClaims("iss", "sub", "aud", "exp", "iat", "jti", "client_id")
}

func verificationRule(token *jwt.Token, _ jwt.VerificationConfig) error {
	for _, signature := range token.Signatures() {
		if signature.ProtectedHeader.Type != "at+jwt" {
			return fmt.Errorf("profile: typ is %q", signature.ProtectedHeader.Type)
		}
	}

	return token.RequireClaims("client_id")
}
```

The producer gives its rule with `WithIssuanceRule`, and the recipient gives its rule with
`WithRule`:

```go
token, err := jwt.NewToken(
	jwt.WithType("at+jwt"),
	jwt.WithIssuer("https://issuer.example"),
	jwt.WithPrivateClaim("client_id", "s6BhdRkqt3"),
	jwt.WithSignature(jwa.ES256(), key, jws.WithProtectedHeader(header.WithKeyID(key.ID()))),
	jwt.WithIssuanceRule(issuanceRule),
)

config := jwt.NewVerificationConfig(
	jwt.WithAlgorithms(jwa.ES256()),
	jwt.WithExpectedIssuer("https://issuer.example"),
	jwt.WithExpectedAudience("https://api.example"),
	jwt.WithLeeway(30*time.Second),
	jwt.WithRule(verificationRule),
)
```

The rules collect, and each rule must accept the token. Two options for two different profiles
give the two rules, and not a result with no indication where only the last rule applies.

`Token.AddProtectedHeader` lets an issuance rule complete the header of one signature. A
parameter that comes from the key of a signature is not a value that the caller can give,
because the same options select the key.

`Token.VerifySignature` checks one signature against one key set. A profile with a
specification that names the key must use that method. A signature that verifies through
`Token.Verify` shows only that one key of the recipient was the key of the signer.

## Algorithms

A function supplies each algorithm. `jwa.ByName` finds one from its `alg` or `enc` name, and
`jwa.Algorithms` gives all of them.

### Signature algorithms

As `alg` values.

| Name | Constructor | Key |
| --- | --- | --- |
| `HS256`, `HS384`, `HS512` | `jwa.HS256()`, `jwa.HS384()`, `jwa.HS512()` | `[]byte` |
| `RS256`, `RS384`, `RS512` | `jwa.RS256()`, `jwa.RS384()`, `jwa.RS512()` | RSA |
| `PS256`, `PS384`, `PS512` | `jwa.PS256()`, `jwa.PS384()`, `jwa.PS512()` | RSA |
| `ES256`, `ES384`, `ES512` | `jwa.ES256()`, `jwa.ES384()`, `jwa.ES512()` | ECDSA |
| `EdDSA` | `jwa.EdDSA()` | Ed25519 |
| `Ed25519` | `jwa.Ed25519()` | Ed25519 |
| `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | `jwa.MLDSA44()`, `jwa.MLDSA65()`, `jwa.MLDSA87()` | ML-DSA |
| `none` | `jwa.None()` | none |

`Ed25519` names the curve in the `alg` value, and `EdDSA` does not.

The three `ML-DSA` algorithms are from RFC 9964. They are post-quantum, and their key is a
`crypto/mldsa` key in an `AKP` JWK. They are also much larger than the others: the smallest
public key is 1312 octets and the smallest signature is 2420, against 32 and 64 for `Ed25519`.
A deployment with a limit on the size of a token must know that before it selects one of them.
A JWK Thumbprint `kid` is the way to name such a key and not repeat it.

### Key management algorithms

As `alg` values.

| Name | Constructor | Key |
| --- | --- | --- |
| `dir` | `jwa.Dir()` | `[]byte` |
| `RSA1_5` (decryption only) | `jwa.RSA15()` | RSA |
| `RSA-OAEP`, `RSA-OAEP-256` | `jwa.RSAOAEP()`, `jwa.RSAOAEP256()` | RSA |
| `A128KW`, `A192KW`, `A256KW` | `jwa.A128KW()`, `jwa.A192KW()`, `jwa.A256KW()` | `[]byte` |
| `A128GCMKW`, `A192GCMKW`, `A256GCMKW` | `jwa.A128GCMKW()`, `jwa.A192GCMKW()`, `jwa.A256GCMKW()` | `[]byte` |
| `ECDH-ES` | `jwa.ECDHES()` | ECDSA, X25519 |
| `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` | `jwa.ECDHESA128KW()`, `jwa.ECDHESA192KW()`, `jwa.ECDHESA256KW()` | ECDSA, X25519 |
| `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW` | `jwa.PBES2HS256A128KW()`, `jwa.PBES2HS384A192KW()`, `jwa.PBES2HS512A256KW()` | password |

### Content encryption algorithms

As `enc` values.

| Name | Constructor |
| --- | --- |
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | `jwa.A128CBCHS256()`, `jwa.A192CBCHS384()`, `jwa.A256CBCHS512()` |
| `A128GCM`, `A192GCM`, `A256GCM` | `jwa.A128GCM()`, `jwa.A192GCM()`, `jwa.A256GCM()` |

### Two differences

**`RSA1_5` decrypts and does not encrypt, and it is not a default.** RFC 8725 section 3.2 tells
each application to "Avoid all RSA-PKCS1 v1.5 encryption algorithms ..., preferring RSAES-OAEP".
RFC 7519 section 8 tells each implementation with encryption to supply `RSA1_5`. This module does
the two things that satisfy both. `jwa.RSA15` has no `EncryptKey` method and no `WrapKey` method,
thus it is a `jwa.KeyDecrypter` and is not a `jwa.KeyEncrypter`: no token that this module writes
has that padding, and no option changes this. `DefaultDecryptionConfig` does not accept `RSA1_5`,
thus a token that names it gets `ErrForbiddenKeyManagement`. To read such a token, give the
algorithm to `WithKeyManagementAlgorithms`.

The attack that the advice is about is the Bleichenbacher adaptive chosen ciphertext attack, and
it needs an oracle that tells correct padding from incorrect padding. `jwa.RSA15` gives no such
oracle. It makes a random CEK of the length that the `enc` algorithm gives, and the unwrap
operation writes the message on that value only when the padding is correct. Thus an incorrect
padding is not an error. It becomes an unsuccessful tag check, which is `jwa.ErrDecryptionFailed`,
as each other failure of a token is. This is the countermeasure that RFC 7516 section 11.5
recommends.

**`none` is available and is not a default.** `DefaultVerificationConfig` accepts each signature
algorithm of this module other than `none`. `jwa.Algorithms` holds `none`, thus a caller that
uses that result as an allowlist must remove it first.

## Security considerations

The properties below are in the code, and each one names the identifier that applies it.

**A token does not select its own algorithm.** `DefaultVerificationConfig` refuses `none`.
`WithAlgorithms` gives the permitted algorithms, and `WithRequiredAlgorithms` makes them fewer.
The second option makes an intersection with the value of the caller and cannot make the
permitted set larger. This module applies the limit after each option operates, thus the limit
holds for each sequence of the two options. A signature with an algorithm that the
configuration does not accept gives `ErrForbiddenAlgorithm`.

**A token of one kind does not pass as a token of a different kind.** This module checks the
`typ` of the header that authenticated the token, and it does this with no option. A recipient
that gives no option accepts `JWT` and a header with no `typ`, and it rejects each other media
type with `ErrUnexpectedType`. `WithExpectedType` gives the media type of a profile, which is
the explicit typing, and `WithAnyType` removes the check. The value comes from the header that a
key of the recipient authenticated, never from a signature that no key accepted.

**A JWE names its own `alg` and `enc`, thus a recipient limits the two.**
`WithKeyManagementAlgorithms` and `WithContentEncryptionAlgorithms` give the permitted values,
and a token that names a different value gives `ErrForbiddenKeyManagement`.

**The key that a token holds is not a key of trust.** The `jwk` header parameter is a
candidate for verification only through `WithHeaderKey` with a `HeaderKeyPolicy`, and only if
that policy accepts it. This module adds such a key to the candidates of the caller and does not
replace them, thus a token that verifies with a published key continues to verify. Before a
policy operates, this module refuses private key material with `ErrPrivateHeaderKey` and a
symmetric key with `ErrSymmetricHeaderKey`. A secret in a protected header is a secret that the
producer published. See [headerkey.go](headerkey.go).

**A token cannot name the address of a request.** `jku`, `x5u` and the `jku` member of a `cnf`
claim parse as a URI and stay as a URI. No package gets the resource that one of them names. A
token that named its own key set would name the party that says which key signed it, and it
would also make this process address a host of its selection.

The [jwk/remote](jwk/remote) package is the one package with a networking import, and it gets
only the address that the caller gave to `remote.NewSource`. That address must be `https`, and
the package gives `ErrInsecureURL` for each other scheme. A program that does not import that
package cannot make a request at all, and its list of imports shows that.

A token can cause a request to that one address. `Token.Verify` calls `Refresh` on a
`jwk.Refresher` when the `kid` of the token names a key that the recipient does not hold, and
`kid` comes from the sender. The address is still the address of the caller, and the sender
selects only whether that request happens. Two limits hold it: this module gets the keys again
for `jwk.ErrNoSuitableKey` and not for a signature that fails, and `remote.Source` refuses a
request inside its minimum interval with `ErrTooSoon`. Thus many tokens that name a key of no
one make one request. A caller that wants no such request gives a source with no `Refresh`
method, and `*jwk.KeySet` is one.

**A JWE decompresses and does not compress.** The [jwe](jwe) package reads a `zip` parameter and
writes none, and it refuses to compress before it encrypts with `ErrCompressedPlaintext`.
Compression before encryption gives the length of the plaintext to an attacker. Decompression
stops at 16 MiB with `ErrOversizedPlaintext`.

**The header package refuses what it cannot apply.** A `crit` value that names an extension
which this module does not supply gives `ErrUnsupportedCriticalParameter`, and a `b64` value of
`false` gives `ErrUnencodedPayload`. A parameter that a recipient does not understand is not a
parameter that it can ignore.

**A duplicate member name is an error.** `encoding/json/v2` gives
`jsontext.ErrDuplicateName` for a member name two times in a header, a claims set or a JWK. The
JWS Protected Header and the JWS Unprotected Header must also hold no name together, and
`jws.Signature.Disjoint` applies that rule.

**The `cnf` claim obeys its rules.** A claim that names more than one key gives
`ErrMultipleConfirmationKeys`, and this module does not select one of the two with no
indication. A symmetric key in the `jwk` member of a token that is not encrypted gives
`ErrUnprotectedConfirmationKey`, because such a token publishes its own secret. The claim tells
a party to prove possession of that same secret. A claim with no `sub` and no `iss` gives
`ErrUnidentifiedPresenter`, because a token that does not name the presenter gives possession to
nobody.

**A signature and encryption apply in the correct sequence.** `WithSignature` with
`WithEncryption` signs first and encrypts second, which is the necessary sequence.

## Packages

| Package | Function |
| --- | --- |
| [`jwt`](.) | JSON Web Token. The claims, the signatures on them, and the verification. |
| [`jwa`](jwa) | JSON Web Algorithms. The signature, key management and content encryption algorithms. |
| [`jwe`](jwe) | JSON Web Encryption. The JWE object, independently of a JWT. |
| [`jwk`](jwk) | JSON Web Key. A key, a key set, the source that gives a key set, and the thumbprints. |
| [`jws`](jws) | JSON Web Signature. One signature, with its two headers. |
| [`header`](header) | The JOSE header, which the two objects share. |
| [`jwk/remote`](jwk/remote) | A JWK Set that comes from an https address that the caller gives. It is the one package with a networking import. |

The full documentation of each package is at
[pkg.go.dev](https://pkg.go.dev/github.com/iscultas/jwt-go).

## Benchmarks

[benchmark/](benchmark) compares this module with the two other JOSE libraries for Go:
`github.com/golang-jwt/jwt/v5` v5.3.1, which implements JWS and JWT, and
`github.com/lestrrat-go/jwx/v3` v3.2.0, which implements the five specifications that this
module implements. The suite is a module of its own, thus the two libraries that it measures
are not dependencies of this one.

| | |
| --- | --- |
| Machine | Apple M4 Max, darwin/arm64, on mains power |
| Go | 1.27.0 |
| Date | 2026-09-08 |
| Samples | 10 for each benchmark |
| Statistics | `benchstat`, median with a 95% confidence interval |

Every token in the suite holds the seven registered claims of RFC 7519 section 4.1 and one
private claim, each library gets the same key material and the same octets to read, and each
verification is given an algorithm allowlist, the expected issuer, the expected audience and
the expiry. A percentage compares with this module, and `~` says that `benchstat` found no
difference larger than the noise.

### Signing

#### Time

| Algorithm | jwt-go | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 1.951 µs | 1.992 µs (+2.08%) | 3.084 µs (+58.05%) |
| `RS256` | 718.7 µs | 712.7 µs (-0.84%) | 818.3 µs (+13.86%) |
| `PS256` | 715.7 µs | 715.9 µs (~) | 810.7 µs (+13.29%) |
| `ES256` | 15.55 µs | 17.75 µs (+14.20%) | 20.00 µs (+28.63%) |
| `EdDSA` | 14.22 µs | 14.31 µs (+0.64%) | 26.31 µs (+85.05%) |

#### Allocations

| Algorithm | jwt-go | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 29 | 44 (+51.72%) | 75 (+158.62%) |
| `RS256` | 27 | 42 (+55.56%) | 127 (+370.37%) |
| `PS256` | 32 | 47 (+46.88%) | 133 (+315.62%) |
| `ES256` | 85 | 103 (+21.18%) | 156 (+83.53%) |
| `EdDSA` | 24 | 41 (+70.83%) | 78 (+225.00%) |

### Verification

#### Time

| Algorithm | jwt-go | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 2.167 µs | 2.706 µs (+24.87%) | 6.635 µs (+206.16%) |
| `RS256` | 23.41 µs | 23.90 µs (+2.09%) | 28.21 µs (+20.50%) |
| `PS256` | 23.81 µs | 24.45 µs (+2.69%) | 28.64 µs (+20.29%) |
| `ES256` | 37.58 µs | 37.60 µs (~) | 42.44 µs (+12.93%) |
| `EdDSA` | 28.39 µs | 28.68 µs (+1.05%) | 33.20 µs (+16.96%) |

#### Allocations

| Algorithm | jwt-go | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 26 | 46 (+76.92%) | 144 (+453.85%) |
| `RS256` | 31 | 51 (+64.52%) | 165 (+432.26%) |
| `PS256` | 35 | 55 (+57.14%) | 169 (+382.86%) |
| `ES256` | 42 | 62 (+47.62%) | 186 (+342.86%) |
| `EdDSA` | 20 | 40 (+100.00%) | 154 (+670.00%) |

A difference in either table is the cryptography or the encoding, and the cryptography is the
same primitive of the same standard library in all three libraries. A third benchmark holds the
cryptography out: to decode a token and read its claims with no check of the signature takes
1.538 µs here, 2.233 µs in golang-jwt and 5.753 µs in jwx, with 17 allocations against 37 and
125. What remains in the two tables above and is not cryptography is the encoding.

### Encryption and JWK

**golang-jwt has no arm in these benchmarks.** That library implements JWS and JWT only: it has
no JWE at all, and a caller of it supplies a crypto key through a `Keyfunc` and not through a
JWK. Its absence is a difference in what the libraries do, and not an omission from the suite.

Against jwx, and with `A256GCM` throughout, this module encrypts a token in 2.136 µs with `dir`
and 35.83 µs with `ECDH-ES+A256KW`, where jwx takes 16% to 162% longer, and it decrypts in
2.575 µs to 699.5 µs, where jwx takes 1% to 241% longer. An encryption here allocates 27 to 74
blocks against the 138 to 233 of jwx, and a decryption 26 to 67 against 207 to 327.

The JWK benchmarks read one key from JSON in 926.9 ns against 2.891 µs, write one in 925.8 ns
against 1.210 µs, and take an RFC 7638 thumbprint in 489.9 ns against 1.362 µs. The one row
where jwx is faster is the selection of a key from a set of four, 19.94 ns against 98.82 ns,
and the two operations are not the same: `LookupKeyID` of jwx compares the `kid` only, and
`KeySet.Key` here ranks every key of the set by its `use`, `key_ops`, `alg` and `kid` together,
because RFC 7515 section 4.1.4 makes `kid` a hint that a producer need not send.

### What the numbers do not say

**`ES256` is not the same work in the three libraries.** This module makes a deterministic
ECDSA signature, which RFC 6979 specifies and which RFC 8725 section 3.2 makes desirable, and
the two others draw a random nonce. That row therefore compares two algorithms.

**A benchmark is not a security property.** These libraries do not accept the same tokens, and
a faster library that accepts a token it should refuse is not a better one.

**The numbers belong to one machine.** Run the suite on the hardware and the Go version you
care about. [benchmark/results.md](benchmark/results.md) holds every table of this run, and
[benchmark/README.md](benchmark/README.md) records what each benchmark measures, the rules that
make the arms comparable, and how to run it.

## Requirement coverage

The suites in [conformance/](conformance) come from a machine-readable requirements IR in
[rfc-conformance/ir/](rfc-conformance/ir). Each test holds an `rfc-req: <ID>` marker that names
the requirement it proves, and those markers make the coverage matrix. A test is thus traceable
to a sentence of a specification, and you can see a requirement that has no test.

Each of the 15 documents has 100% coverage of its testable MUST, SHOULD and MAY requirements:

| Document | MUST | SHOULD | MAY |
| --- | --- | --- | --- |
| RFC 7515 | 33 | 2 | 12 |
| RFC 7516 | 42 | 1 | 4 |
| RFC 7517 | 20 | 1 | 16 |
| RFC 7518 | 51 | 6 | 5 |
| RFC 7519 | 23 | 7 | 16 |
| RFC 7520 | 9 | -- | -- |
| RFC 7638 | 10 | -- | 1 |
| RFC 7797 | 4 | 1 | 1 |
| RFC 7800 | 6 | -- | 2 |
| RFC 8037 | 18 | -- | 8 |
| RFC 8725 | 10 | 7 | -- |
| RFC 9278 | 6 | -- | -- |
| RFC 9864 | 4 | 2 | 2 |
| RFC 9964 | 11 | -- | 4 |
| RFC 6979 | 5 | -- | -- |

[rfc-conformance/exclusions.md](rfc-conformance/exclusions.md) holds the 67 requirements that
are not testable, across 11 of the 15 documents. Read that file with the matrices. An exclusion
is a claim about what the implementation does, and a human must make sure that the claim is
honest. An exclusion also goes stale when the implementation changes below it.

```bash
go test ./...
```

The module also has fuzz targets on each decoder that reads input from a party that a caller
does not trust: `FuzzUnmarshal`, `FuzzHeaderJWK`, `FuzzHeaderCertificateChain` and
`FuzzConfirmation` in the root package, and one target or more in
[jws](jws/fuzz_test.go), [jwe](jwe/fuzz_test.go), [jwk](jwk/fuzz_test.go) and
[header](header/fuzz_test.go).

```bash
go test -run '^$' -fuzz FuzzUnmarshal -fuzztime 60s .
```

## Errors

Each package gives its errors as sentinel values, thus a caller tests for one with
`errors.Is`:

```go
switch err := received.Verify(ctx, keys, config); {
case errors.Is(err, jwt.ErrExpired):
	// the "exp" claim is in the past
case errors.Is(err, jwt.ErrUnverified):
	// no key of the set verified a signature
case errors.Is(err, jwt.ErrForbiddenAlgorithm):
	// the token named an algorithm that the configuration does not accept
}
```

The groups are:

- The `jwt` package gives the errors of a token: the structure (`ErrMalformedToken`,
  `ErrMalformedClaim`, `ErrUnsigned`, `ErrMultipleSignatures`), the claims (`ErrExpired`,
  `ErrNotYetValid`, `ErrUnexpectedIssuer`, `ErrUnexpectedSubject`, `ErrUnexpectedAudience`,
  `ErrUnexpectedType`, `ErrTooOld`, `ErrIssuedInFuture`, `ErrReplayedToken`,
  `ErrMissingRequiredClaim`, `ErrReservedClaim`), the policy (`ErrForbiddenAlgorithm`,
  `ErrForbiddenKeyManagement`, `ErrUnverified`), the header key (`ErrHeaderKeyRefused`, `ErrPrivateHeaderKey`,
  `ErrSymmetricHeaderKey`) and the `cnf` claim.
- The `jwa` package gives the errors of an algorithm and a key: `ErrUnsupportedAlgorithm`,
  `ErrInvalidKeyType`, `ErrInvalidKeySize`, `ErrWeakKey`, `ErrSignatureMismatch` and
  `ErrDecryptionFailed`.
- The `jwk` package gives the errors of a key and a certificate: `ErrUnsupportedKeyType`,
  `ErrMalformedKey`, `ErrUnsupportedCurve`, `ErrNoSuitableKey` and the X.509 errors.
- The `jws`, `jwe` and `header` packages give the errors of their objects.
- The `jwk/remote` package gives the errors of a request: `ErrInsecureURL`,
  `ErrUnexpectedStatus`, `ErrOversizedKeySet`, `ErrMalformedKeySet` and `ErrTooSoon`.

`MissingRequiredParameterError` of the `jwk` package names the parameter that a key does not
hold. `errors.As` gives it.

## How to make a change

The module has no dependency external to the standard library, thus the tests need no
preparation:

```bash
go test ./...
```

The checks that [CI](.github/workflows/ci.yml) applies to each change are these:

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
go test -count=1 -coverpkg=./... -coverprofile=coverage.out ./...
```

`-coverpkg=./...` and not the count of one package: the suites in [conformance/](conformance)
are packages of their own that drive the other packages, and a count for one package does not
see what they cover. `go tool cover -func=coverage.out` gives the total.

A fuzz target runs its seed corpus with the usual tests. To look for what the seeds do not
reach, give the target time:

```bash
go test -run '^$' -fuzz '^FuzzUnmarshal$' -fuzztime 60s .
```

CI does that for each target one time each night, and not on each change: a run that finds a
new input fails the job, and a job that can fail for a cause outside the change under test is a
job that a reader learns to ignore. A target that finds an input writes it to `testdata/fuzz/`.
That file is the finding, and it goes in the repository: it is then a seed that runs with the
usual tests and holds the fix in place.

An input is a finding only when it reaches the module. A target builds its own input out of the
fuzz bytes, thus a mutated seed can give a target something that the target itself refuses
before a decoder runs: a thumbprint that is not valid UTF-8 has no JSON encoding, so
`FuzzHeaderCertificateChain` has no header to drive the decoders with and returns. Such a file
records the harness refusing its own input, and it does not go in the repository, because it
holds nothing in place. Two checks tell the two apart. The first is coverage: the profile with
the file is the same as the profile without it, statement for statement, thus the file reaches
no code that the seeds do not.

```bash
go test -run '^FuzzHeaderCertificateChain$' -coverpkg=./... -coverprofile=coverage.out .
```

The second is a mutation: the guard that the file is supposed to hold comes out, and the target
still passes, thus the file does not hold that guard either. A file that both checks answer so
is not a finding. It comes out, and the comment in the target says what the harness refuses.

A change to the behaviour of a requirement needs the coverage matrix of that requirement again.
The matrices are in [rfc-conformance/](rfc-conformance), and the tests that they name are in
[conformance/](conformance). [exclusions.md](rfc-conformance/exclusions.md) holds each
requirement that is not testable, with the reason. An exclusion is a claim about what the code
does, thus a change to the code can make one of them incorrect.

[benchmark/](benchmark) is a module of its own and no other command builds it. A change to the
API of this module can break it:

```bash
cd benchmark && go build ./...
```

## License

Public domain, with the [Unlicense](UNLICENSE). That file holds the full terms.
