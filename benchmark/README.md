# Benchmarks

A comparison of this module with the two other JOSE libraries for Go:

| Library | Version | Scope |
| --- | --- | --- |
| [`github.com/iscultas/jwt-go`](..) | this tree | JWS, JWE, JWK, JWA, JWT |
| [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) | v5.3.1 | JWS and JWT |
| [`github.com/lestrrat-go/jwx/v3`](https://github.com/lestrrat-go/jwx) | v3.2.0 | JWS, JWE, JWK, JWA, JWT |

## Contents

- [How to run](#how-to-run)
- [What each benchmark measures](#what-each-benchmark-measures)
- [Rules that make the comparison fair](#rules-that-make-the-comparison-fair)
- [What the numbers do not say](#what-the-numbers-do-not-say)
- [Why this is a separate module](#why-this-is-a-separate-module)

## How to run

```bash
./bench.sh
```

The script first runs the correctness tests, and then the benchmarks ten times
each. It writes the samples to a file, and prints the command that makes the
table from them:

```bash
go run golang.org/x/perf/cmd/benchstat@latest -col /lib -row '.name,/alg' <samples>
```

Each benchmark name holds the library and the algorithm as `key=value` parts,
for example `BenchmarkVerify/lib=jwx/alg=ES256`. `benchstat` reads such a part
when a slash comes before its name, thus `-col /lib` gives one column for each
library. The first column becomes the one that the others compare to.

[`results.md`](results.md) in this directory holds the last run as tables, with
the machine and the Go version that made it, and it is committed. The samples
that made it are not: they are 62 KB of one machine, and the tables hold what a
reader needs. Read the run with [What the numbers do not
say](#what-the-numbers-do-not-say).

A pattern limits the run:

```bash
./bench.sh BenchmarkVerify
```

`BENCH_COUNT` changes the number of repetitions and `BENCH_OUTPUT` the file.

## What each benchmark measures

| Benchmark | Libraries | Operation |
| --- | --- | --- |
| `BenchmarkSign` | three | Build the claim set, encode it, and make the signature. |
| `BenchmarkVerify` | three | Decode the token, check the signature, and then check the claims. |
| `BenchmarkParse` | three | Decode the token and read the claims, with no check of the signature. |
| `BenchmarkEncrypt` | two | Build the claim set, encode it, protect a Content Encryption Key, and encrypt the claims. |
| `BenchmarkDecrypt` | two | Recover the Content Encryption Key, decrypt the claims, and then check them. |
| `BenchmarkJWKParse`, `BenchmarkJWKMarshal` | two | Read one JWK from JSON, and write one as JSON. |
| `BenchmarkJWKThumbprint` | two | The RFC 7638 thumbprint of one key. |
| `BenchmarkJWKSetLookup` | two | Select one key from a set of four. |

The signature benchmarks use `HS256`, `RS256`, `PS256`, `ES256` and `EdDSA`,
which are the algorithms that all three libraries have. The RSA keys are
2048-bit.

The encryption benchmarks use `dir`, `A256KW`, `ECDH-ES+A256KW` and
`RSA-OAEP-256`, each with `A256GCM`. One content encryption algorithm throughout
keeps the ciphertext the same length in every row, thus the rows differ only in
the key management.

**golang-jwt has no arm in the encryption or the JWK benchmarks.** That library
implements JWS and JWT only: it has no JWE at all, and a caller of it supplies a
crypto key through a `Keyfunc` rather than a JWK. Its absence is a difference in
what the libraries do, and not an omission from this suite.

`BenchmarkParse` is there to explain the two benchmarks above it. A difference in
signing or in verification is either the cryptography or the encoding, and the
cryptography is the same primitive from the same standard library in all three.
This benchmark holds the cryptography out, thus what remains is the encoding.

## Rules that make the comparison fair

**One claim set.** Every token in the suite holds the seven registered claims of
RFC 7519 section 4.1 and one private claim. Thus every library encodes and
decodes the same quantity of JSON. A private claim is in the set because the
three libraries hold one in three different ways, and a token with registered
claims only would hide that difference.

**One set of keys.** The key material is made once, before the first benchmark,
and each library gets the same octets. Thus a difference in a result comes from
the library and not from the key. The material is made and not read from a
fixture, because a fixture with a private key in it is a secret in the
repository.

**One set of octets to read.** The verification, parsing and decryption
benchmarks give all the arms the same serialized token. Thus each arm decodes
the same base64 and the same JSON. This module produces those tokens, which
gives it no advantage: a producer cannot make its own output cheaper for itself
to parse than for another library to parse.

**The same checks on every arm.** Each verification is given an algorithm
allowlist, the expected issuer, the expected audience, and the expiry. This
matters most for golang-jwt, which checks the issuer and the audience only when
it is told to; a verification with fewer checks is not the same operation.

**Idiomatic use of each library.** The claims go into a struct that embeds
`jwt.RegisteredClaims` for golang-jwt, into a builder for jwx, and into
functional options here. Each is what that library's documentation tells a
caller to write. A common denominator would measure an adapter and not a
library.

**Setup outside the loop.** Key generation, key import, the parser and the
verification configuration are all made before the timed loop, as a server makes
them once at startup.

**A new token on each iteration of `BenchmarkSign`.** A `jwt.Token` of this
module signs once: `Token.sign` sets `pending` to nil and is documented as
idempotent. A token that is made outside the loop would therefore measure a
cached string from the second iteration, and would report a signature that costs
almost nothing. The two other arms build their claim carrier in the loop as
well, so that all three pay for the claim set. `TestTokenSignsOnce` fails if this
rule ever stops holding.

**Every arm is checked before it is timed.** `TestSignatureArmsAgree` gives every
token of every library to every library, and `TestEncryptionArmsAgree` does the
same for the two libraries that have JWE. A benchmark that measures nothing
still reports a time; an arm with the wrong key or a check that never runs is
not visible in the output. `TestHeadersAreComparable` checks that all three
libraries write `alg`, `typ` and `kid`, since a library that writes fewer
parameters gives itself a shorter token to produce and to read. `bench.sh` runs
these tests first.

## What the numbers do not say

**`ES256` is not the same work in all three libraries.** This module makes a
deterministic ECDSA signature, which RFC 6979 specifies and which RFC 8725
section 3.2 makes desirable: a repeated nonce discloses the private key.
golang-jwt and jwx draw a random nonce from `crypto/rand`. The `ES256` row of
`BenchmarkSign` therefore compares two different algorithms. This is a
difference in what the libraries guarantee, not a defect in the measurement.

**`BenchmarkJWKSetLookup` compares two different operations.** jwx gives
`LookupKeyID`, which compares the `kid` only. This module gives `KeySet.Key`,
which ranks every key of the set by its `use`, `key_ops`, `alg` and `kid`
together, because RFC 7515 section 4.1.4 makes `kid` a hint that a producer need
not send. This module does more work here, deliberately.

**`BenchmarkDecrypt` needs two calls for jwx.** `jwt.Parse` of that library reads
a JWS and not a JWE, thus the arm calls `jwe.Decrypt` and then `jwt.Parse`.
`Token.Decrypt` of this module is one call that does both. Both jwx calls are
inside the loop, since together they are the one operation.

**A benchmark is not a security property.** These libraries do not accept the
same tokens. This module writes no `RSA1_5` token and reads one only when a
caller names the algorithm, which is what RFC 8725 section 3.2 asks, and it gives
no claim to a caller until a key has verified the token. A faster library that
accepts a token it should refuse is not a better one.

**The numbers belong to one machine.** [`results.md`](results.md) names the one
machine and the one Go version that made it, and no other hardware is under it.
Run the suite on the hardware and the Go version you care about.

## Why this is a separate module

The module at the root of this repository has no dependency external to the
standard library, and that property is the first thing its README states. These
benchmarks need two external dependencies. They are therefore in a module of
their own, with a `replace` that points at the tree above it:

```
replace github.com/iscultas/jwt-go => ../
```

Go leaves a directory with its own `go.mod` out of the packages of the module
above it. Thus `go build ./...` and `go test ./...` at the root are unchanged,
the root `go.mod` gains no `require`, and the root has no `go.sum`. The
`replace` makes the suite measure this working tree and not a published version.
