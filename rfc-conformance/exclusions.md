# Deliberately excluded requirements

Every requirement across the IR set marked `not-testable`, with the reason it carries. Generated from the IR; edit the IR, not this file.

65 requirements across 11 of the 15 documents; the other 4 exclude nothing. An exclusion is a claim about what the implementation does, so each one goes stale when the implementation changes underneath it. Re-read them against the code rather than against this file.

When you do re-read them, keep the kinds apart. A claim about what the code does can be checked mechanically and can be proven wrong. A judgement that something is the caller's obligation, or the deployment's, has to be read against the specification sentence and the API boundary. A deferral to another requirement is checked below. Guidance aimed at IANA, at document authors, or at operators turns only on the text. Report how many were verified by running something and how many by reading -- those are different strengths of evidence and summing them overstates both.

| Document | Excluded |
| --- | --- |
| RFC6979 | 1 |
| RFC7515 | 16 |
| RFC7517 | 16 |
| RFC7518 | 5 |
| RFC7519 | 10 |
| RFC7638 | 2 |
| RFC7797 | 7 |
| RFC7800 | 4 |
| RFC8037 | 1 |
| RFC8725 | 2 |
| RFC9964 | 1 |

## Deferrals to other excluded requirements

Each of these exclusions points at a requirement that is itself excluded, or at one that does not exist. Sometimes the pair is legitimate -- each standing on its own ground and citing the other only for context -- but that is a judgement somebody has to make and record, not a default.

All of them have been reviewed: each is named in its requirement's `deferral_review`, with the reasoning in the rationale beside it. They stay listed rather than disappearing, because a reader deserves to see what was decided as well as what is left.

| Exclusion | Cites | State |
| --- | --- | --- |
| `RFC7515-S8-R01` | `RFC7515-S4_1_2-R01` | also excluded, reviewed |
| `RFC7515-S8-R01` | `RFC7515-S4_1_5-R01` | also excluded, reviewed |
| `RFC7515-S10_12-R06` | `RFC7515-S4-R05` | also excluded, reviewed |
| `RFC7517-S4_3-R05` | `RFC7517-S4_3-R04` | also excluded, reviewed |
| `RFC7517-S7-R01` | `RFC7517-S9_2-R01` | also excluded, reviewed |
| `RFC7517-S7-R01` | `RFC7519-S12-R01` | also excluded, reviewed |
| `RFC7517-S9_2-R01` | `RFC7517-S7-R01` | also excluded, reviewed |
| `RFC7518-S4_8-R01` | `RFC7518-S9-R01` | also excluded, reviewed |
| `RFC7518-S9-R01` | `RFC7518-S4_8-R01` | also excluded, reviewed |
| `RFC7800-S3_5-R02` | `RFC7515-S4_1_2-R01` | also excluded, reviewed |
| `RFC7800-S3_5-R02` | `RFC7515-S4_1_5-R01` | also excluded, reviewed |
| `RFC7800-S3_5-R03` | `RFC7515-S4_1_6-R01b` | also excluded, reviewed |

## RFC6979 — Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)

### `RFC6979-S4-R01` (SHOULD, section 4)

> The determinism of the algorithms described in this note may be useful to an attacker in some forms of side-channel attacks, so implementations SHOULD use defensive measures to avoid leaking the private key through a side channel.

A signature produced with side-channel leakage is bit-identical to one produced without, so no assertion over jwa's inputs and outputs can distinguish them. Demonstrating the property needs timing and power measurement of the underlying field arithmetic, which is the standard library's and not this module's.

## RFC7515 — JSON Web Signature (JWS)

### `RFC7515-S2-R01` (MAY, section 2)

> StringOrURI A JSON string value, with the additional requirement that while arbitrary string values MAY be used, any value containing a ":" character MUST be a URI [RFC3986]. StringOrURI values are compared as case-sensitive strings with no transformations or canonicalizations applied.

StringOrURI is defined here as shared terminological groundwork but this specification defines no Header Parameter of its own with this type — every registered JWS Header Parameter (alg, jku, kid, typ, cty, crit, ...) is typed as a plain string, URI, or array in Section 4.1, never as StringOrURI. The values that actually use this type ("iss", "sub", "aud") are JWT Claims defined by RFC 7519, out of this suite's RFC 7515 scope.

### `RFC7515-S3_2-R02` (MAY, section 3.2)

> The inclusion of some of these values is OPTIONAL.

A generic restatement of the per-member optionality that Section 7.2.1 states precisely for each member ("payload" and "signature" always required; "protected"/"header" conditionally required per RFC7515-S3_2-R01, RFC7515-S7_2_1-R03, RFC7515-S7_2_1-R04 and RFC7515-S7_2_1-R06). It adds no independent, separately observable behaviour beyond those already-enriched requirements.

Defers to: `RFC7515-S3_2-R01` (covered), `RFC7515-S7_2_1-R03` (covered), `RFC7515-S7_2_1-R04` (covered), `RFC7515-S7_2_1-R06` (covered)

### `RFC7515-S4-R05` (MUST, section 4)

> The Header Parameter names within the JOSE Header MUST be unique; JWS parsers MUST either reject JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].

header.Header is a closed struct of typed fields and header.Header.MarshalJSON composes the JOSE Header by populating a rawHeader struct and handing that to encoding/json/v2. There is no map of caller-supplied members and no way to name one twice, so a header this package composes cannot carry a duplicate; the obligation is discharged by the API shape rather than by a code path a test could drive to failure. One path emits header octets this package did not compose: header.Header.Marshal returns the recorded octets verbatim when they are set, because re-emitting them unchanged is what lets a signature verify over the bytes that were signed. header.Header.Unmarshal no longer records octets carrying a duplicate: it decodes before it records, and that decode is the rejection tested at RFC7515-S4-R01 (verified empirically -- a header carrying two "kid" members returns an error wrapping jsontext.ErrDuplicateName, and Header.Encoded is left empty). The one remaining way to reach Marshal with such octets is header.Header.SetEncoded, whose own documentation names it dangerous and whose purpose is to let a caller supply octets this package did not compose. Uniqueness in those octets was the obligation of whoever composed them. This requirement is the retrofitted producer half of the sentence whose parser half is RFC7515-S4-R01.

Defers to: `RFC7515-S4-R01` (covered)

### `RFC7515-S4-R02` (MUST, section 4)

> Implementations are required to understand the specific Header Parameters defined by this specification that are designated as "MUST be understood" and process them in the manner defined in this specification.

A general statement of obligation with no oracle of its own beyond the per-parameter requirements that already exist for the two parameters this specification designates "MUST be understood": "alg" (RFC7515-S4_1_1-R01) and "crit" (RFC7515-S4_1_11-R01/R05/R07). Testing it again here would duplicate those tests without adding coverage.

Defers to: `RFC7515-S4_1_1-R01` (covered), `RFC7515-S4_1_11-R01` (covered)

### `RFC7515-S4-R03` (MUST, section 4)

> All other Header Parameters defined by this specification that are not so designated MUST be ignored when not understood.

This package implements every currently registered non-"MUST-be-understood" Header Parameter this specification defines (jku, jwk, kid, x5u, x5c, x5t, x5t#S256, typ, cty) — it always recognizes them, so the "registered but not understood by this implementation" case this sentence addresses cannot be exercised. The parallel case this package can and does exercise — a Header Parameter this specification never defines at all (private/public names) — is covered by RFC7515-S4-R04 instead.

Defers to: `RFC7515-S4-R04` (covered)

### `RFC7515-S4_1_2-R01` (MUST, section 4.1.2)

> The keys MUST be encoded as a JWK Set [JWK]. The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the JWK Set MUST use Transport Layer Security (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].

This package never dereferences "jku" — it stores the parsed *url.URL verbatim and performs no HTTP fetch of any kind. No package that decodes a token holds a transport: conformance/rfc8725's TestJKUAndX5UAreNeverDereferenced walks the source and fails on net/http, net/rpc, net/smtp or net/mail appearing in any of it. The walk excludes one package, jwk/remote, which does fetch a JWK Set over TLS — but only from the address a caller passes to remote.NewSource, never from a header parameter: TestTheNetworkingPackageCannotSeeAToken checks that jwk/remote imports no package that decodes a JOSE header or a token, so no "jku" value can reach it. That fetcher is therefore not the code path this MUST governs, and there is still no "jku" fetch code path for this MUST's resource format, integrity-protection, or TLS obligations to bind to. Verification may now call Refresh on a caller-supplied jwk.Refresher when a token's kid names no key the recipient holds; that changes when the caller's own address is fetched, never which address, so it leaves this finding unchanged.

### `RFC7515-S4_1_5-R01` (MUST, section 4.1.5)

> The identified resource MUST provide a representation of the certificate or certificate chain that conforms to RFC 5280 [RFC5280] in PEM-encoded form, with each certificate delimited as specified in Section 6.1 of RFC 4945 [RFC4945]. The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate. [...] The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the certificate MUST use TLS [RFC2818] [RFC5246]; and the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].

This package never dereferences "x5u" — it stores the parsed *url.URL verbatim and performs no HTTP fetch of any kind. No package that decodes a token holds a transport: conformance/rfc8725's TestJKUAndX5UAreNeverDereferenced walks the source and fails on net/http, net/rpc, net/smtp or net/mail appearing in any of it. The walk excludes one package, jwk/remote, which fetches only a JWK Set from the address a caller passes to remote.NewSource, never from a header parameter, and which retrieves no certificate at all: TestTheNetworkingPackageCannotSeeAToken checks that it imports no package that decodes a JOSE header or a token. There is still no "x5u" fetch code path for this MUST's resource format or transport obligations to bind to. Verification may now call Refresh on a caller-supplied jwk.Refresher when a token's kid names no key the recipient holds; that changes when the caller's own address is fetched, never which address, so it leaves this finding unchanged.

### `RFC7515-S4_1_6-R01b` (MUST, section 4.1.6)

> The recipient MUST validate the certificate chain according to RFC 5280 [RFC5280] and consider the certificate or certificate chain to be invalid if any validation failure occurs.

RFC 5280 path validation is a trust decision, and this package holds none of what it needs: no trust anchors, no policy, no clock skew allowance, no revocation source. Which roots to accept is the application's to choose, and crypto/x509.Certificate.Verify already takes that configuration. What this package does enforce is the part that needs none of it -- see RFC7515-S4_1_6-R01a for the signing key's certificate being first, and RFC 7517 section 4.7's chain-order and key-match checks, which verify that each certificate was signed by the next without asking whether any of them should be believed.

Defers to: `RFC7515-S4_1_6-R01a` (covered)

### `RFC7515-S4_1_9-R02` (SHOULD, section 4.1.9)

> To keep messages compact in common situations, it is RECOMMENDED that producers omit an "application/" prefix of a media type value in a "typ" Header Parameter when no other '/' appears in the media type value. [...] For instance, a "typ" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to "example;part="1/2"".

This is a recommendation about which string an application chooses for "typ"; the library stores whatever string the caller provides verbatim, by every route it offers: header.Header.Type is a plain field, and jwt.WithType and jwt.Token.Type -- the setter and getter an application profile uses to declare its own media type -- are a plain assignment and a plain read, with no prefix-adding or prefix-stripping logic anywhere between them. There is no library-level behaviour to assert beyond faithful passthrough, which RFC7515-S4_1_9-R01/S4_1_11 test elsewhere.

Defers to: `RFC7515-S4_1_9-R01` (covered)

### `RFC7515-S4_1_9-R03` (MUST, section 4.1.9)

> A recipient using the media type value MUST treat it as if "application/" were prepended to any "typ" value not containing a '/'.

"This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application" (Section 4.1.9). This package exposes "typ" as a raw string and nothing more -- header.Header.Type, and jwt.Token.Type for a profile reading it back -- with no media-type-comparison helper of its own anywhere, so there is no library-level "recipient using the media type value" for this MUST to bind to. A profile that compares the value does so in its own code, on a string this package handed over unexamined — the obligation falls entirely on application code this package does not provide.

### `RFC7515-S4_1_11-R02d` (MUST, section 4.1.11)

> Producers MUST NOT include Header Parameter names defined by this specification or [JWA] for use with JWS, duplicate names, or names that do not occur as Header Parameter names within the JOSE Header in the "crit" list. Producers MUST NOT use the empty list "[]" as the "crit" value.

Satisfied by construction, and recorded here rather than claimed as coverage. The "crit" member carries `json:"crit,omitempty"` (header/header.go), so an empty or nil Critical slice is omitted from the serialized header entirely; there is no input a caller can supply that makes this package emit "crit":[]. A test would assert the absence of a member rather than the refusal of a value, which is a property of encoding/json rather than evidence about this rule.

### `RFC7515-S6-R01` (MUST, section 6)

> These Header Parameters MUST be integrity protected if the information that they convey is to be utilized in a trust decision; however, if the only information used in the trust decision is a key, these parameters need not be integrity protected, since changing them in a way that causes a different key to be used will cause the validation to fail.

Whether a given key-identifying parameter's value "is utilized in a trust decision" is an application-level fact this generic library cannot know: it permits kid/jku/x5u/etc. on either the protected or unprotected header without restriction (unlike "crit", which it does restrict), correctly leaving that trust-relevant placement choice to the application. Errata 7767 against this exact sentence ("Reported", not yet verified by RFC Editor) proposes deleting the trailing exception clause as incorrect for both signature and encryption schemes; either reading leaves the obligation conditional on an application trust decision this package does not make.

### `RFC7515-S6-R02` (SHOULD, section 6)

> The producer SHOULD include sufficient information in the Header Parameters to identify the key used, unless the application uses another means or convention to determine the key used.

"Sufficient information to identify the key" has no library-checkable criterion — what counts as sufficient depends entirely on the application's own key-lookup scheme (a single fixed key needs none; a large rotating key set might need kid, x5t, and more). The library supplies the mechanism (kid, x5u, x5c, x5t, x5t#S256 header fields) but cannot judge sufficiency.

### `RFC7515-S8-R01` (MUST, section 8)

> Implementations supporting the "jku" and/or "x5u" Header Parameters MUST support TLS. [...] To protect against information disclosure and tampering, confidentiality protection MUST be applied using TLS with a ciphersuite that provides confidentiality and integrity protection. [...] Whenever TLS is used, the identity of the service provider encoded in the TLS server certificate MUST be verified using the procedures described in Section 6 of RFC 6125 [RFC6125].

This package does not support (does not implement) dereferencing "jku" or "x5u" at all — it never fetches the resource either parameter names — so it is not an implementation this Section's TLS obligations bind to; there is no transport of its own on that path to test. See RFC7515-S4_1_2-R01 and RFC7515-S4_1_5-R01 for the parallel not-testable finding on the resource-format side of the same gap. Those two are cited as parallels: this exclusion rests on the absence of any fetch code path for a header-supplied URI, which conformance/rfc8725's TestJKUAndX5UAreNeverDereferenced and TestTheNetworkingPackageCannotSeeAToken check together — the first that no token-bearing package can make a request, the second that the one package which can (jwk/remote) cannot read a token. jwk/remote does require https for the address a caller gives it, but a caller-configured JWK Set URL is not the "jku" or "x5u" this Section conditions on. This exclusion would stand unchanged if either cited requirement became testable. Verification may now call Refresh on a caller-supplied jwk.Refresher when a token's kid names no key the recipient holds; that changes when the caller's own address is fetched, never which address, so it leaves this finding unchanged.

Defers to: `RFC7515-S4_1_2-R01` (also excluded, reviewed), `RFC7515-S4_1_5-R01` (also excluded, reviewed)

### `RFC7515-S10_12-R02` (SHOULD, section 10.12)

> Section 4 of "The JavaScript Object Notation (JSON) Data Interchange Format" [RFC7159] states, "The names within an object SHOULD be unique", whereas this specification states [...] Thus, this specification requires that the "SHOULD" in Section 4 of [RFC7159] be treated as a "MUST" by producers and that it be either treated as a "MUST" or treated in the manner specified in ECMAScript 5.1 by consumers.

This is the RFC explaining its own relationship to RFC 7159, not a new obligation distinct from the uniqueness/last-wins rule already enriched as RFC7515-S4-R01 (which this passage exists to justify). No independent oracle exists beyond that already-tested rule.

Defers to: `RFC7515-S4-R01` (covered)

### `RFC7515-S10_12-R06` (MUST, section 10.12)

> The Header Parameter names within the JOSE Header MUST be unique; JWS parsers MUST either reject JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].

Section 10.12 restates section 4's sentence verbatim, and the finding is the one recorded at RFC7515-S4-R05: this package composes JOSE Headers from a closed struct, so a duplicate member name is not expressible, and the only verbatim passthrough emits octets a caller supplied through SetEncoded rather than octets this package composed or decoded. Cited as the same finding on a restated sentence, not as ground this exclusion borrows. This requirement is the retrofitted producer half of the sentence whose parser half is RFC7515-S10_12-R03.

Defers to: `RFC7515-S10_12-R03` (covered), `RFC7515-S4-R05` (also excluded, reviewed)

## RFC7517 — JSON Web Key (JWK)

### `RFC7517-S4-R04` (MUST, section 4)

> The member names within a JWK MUST be unique; JWK parsers MUST either reject JWKs with duplicate member names or use a JSON parser that returns only the lexically last duplicate member name, as specified in Section 15.12 (The JSON Object) of ECMAScript 5.1 [ECMAScript].

jwk.Key.MarshalJSON composes the document by populating a rawKey struct of typed fields and handing it to encoding/json/v2. The key holds no map of caller-supplied members, so no member name can be written twice and the obligation is discharged by the API shape rather than by a code path a test could drive to failure. This requirement is the retrofitted producer half of the sentence whose parser half is RFC7517-S4-R02.

Defers to: `RFC7517-S4-R02` (covered)

### `RFC7517-S4_3-R04` (SHOULD, section 4.3)

> Multiple unrelated key operations SHOULD NOT be specified for a key because of the potential vulnerabilities associated with using the same key with multiple algorithms.

"Unrelated" is a semantic judgment about an application's key-management policy (why a given key exists), not a property jwk.Key or jwk.KeySet can compute from the operations list alone. jwk.checkOperations, which both MarshalJSON and UnmarshalJSON run, enforces the two rules of section 4.3 that are mechanical -- no operation named twice, and no operation contradicting a "use" declared beside it -- and deliberately not this one, since relatedness is not computable from the list. WithOperations stores its argument slice verbatim and checks nothing at all; the check happens at the encoding boundary, where the document is. Asserting this rule would require inventing a policy the RFC does not specify mechanically.

### `RFC7517-S4_3-R05` (SHOULD, section 4.3)

> Thus, the combinations "sign" with "verify", "encrypt" with "decrypt", and "wrapKey" with "unwrapKey" are permitted, but other combinations SHOULD NOT be used.

Which combinations of key operations count as related is a statement about why an application holds a key, so this sentence constrains what an application chooses to write into key_ops rather than anything jwk can compute from the list it is given. The combination this sentence names as forbidden is accepted: {sign, decrypt} marshals and unmarshals unchanged (verified empirically against the module -- re-run it rather than trusting this sentence). Where the module does draw a line it is drawing a different one -- add "use":"sig" to that same key and both directions refuse it with jwk.ErrInconsistentKeyUse, because section 4.3 also requires key_ops and use to be consistent, and that rule is mechanical where this one is not. So the pairs listed here are neither enforced nor enforceable on their own. RFC7517-S4_3-R04 states the same rule in general terms and is excluded on this same ground; it is a parallel finding cited for context, not the reason this one holds.

Defers to: `RFC7517-S4_3-R04` (also excluded, reviewed)

### `RFC7517-S4_3-R07` (SHOULD, section 4.3)

> The "use" and "key_ops" JWK members SHOULD NOT be used together; however, if both are used, the information they convey MUST be consistent.

Which of the two members to write is a decision taken by whoever composes the JWK, and this package composes a JWK from whatever the caller sets: jwk.WithPublicKeyUse and jwk.WithOperations are independent options and neither refuses the other. Declining to enforce this SHOULD NOT is required rather than merely permitted -- the same sentence goes on to say what must hold *if* both are used, and RFC7517-S4_3-R06 tests exactly that, so a library that refused the combination outright could not implement the rule beside it. R06's accepting cases already demonstrate that both members together are carried rather than rejected. Recorded so the deviation is visible: this package does not follow the SHOULD NOT, deliberately, and the obligation stays with the application that decides what to put in the key.

Defers to: `RFC7517-S4_3-R06` (covered)

### `RFC7517-S4_5-R01` (SHOULD, section 4.5)

> When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.

Verified empirically: jwk.NewKeySet with two keys sharing a kid builds and marshals without error, and a JWK Set document with two such entries decodes without error. Deliberately left that way. Section 4.5 states the obligation and then names its own exception -- "One example in which different keys might use the same kid value is if they have different kty values but are considered to be equivalent alternatives by the application using them" -- so a consumer that refused such a set would reject documents the specification sanctions. Whether two same-kid keys are equivalent alternatives or a producer error is a judgment about the application's key management that jwk.KeySet has no way to make. The same class of application-assigned-property obligation as RFC 7519's sub and jti uniqueness requirements.

### `RFC7517-S4_6-R01` (MUST, section 4.6)

> The identified resource MUST provide a representation of the certificate or certificate chain that conforms to RFC 5280 [RFC5280] in PEM-encoded form, with each certificate delimited as specified in Section 6.1 of RFC 4945 [RFC4945].

This obligation is about the resource "x5u" names, and answering it requires fetching that resource: an HTTPS GET, a TLS trust store, and RFC 6125 identity validation. jwk performs no network I/O and holds "x5u" as a *url.URL it never dereferences, so no certificate is ever in hand to judge. That is a deliberate boundary rather than a gap -- a library that fetched URLs named in the documents it parses would be an SSRF primitive -- and it is the caller, holding the fetched certificate, who can apply this. The same sentence appears in section 4.7 about a certificate the JWK itself carries, and there it is enforced: see RFC7517-S4_7-R03.

Defers to: `RFC7517-S4_7-R03` (covered)

### `RFC7517-S4_6-R02` (MUST, section 4.6)

> The key in the first certificate MUST match the public key represented by other members of the JWK.

This obligation is about the resource "x5u" names, and answering it requires fetching that resource: an HTTPS GET, a TLS trust store, and RFC 6125 identity validation. jwk performs no network I/O and holds "x5u" as a *url.URL it never dereferences, so no certificate is ever in hand to judge. That is a deliberate boundary rather than a gap -- a library that fetched URLs named in the documents it parses would be an SSRF primitive -- and it is the caller, holding the fetched certificate, who can apply this. The same sentence appears in section 4.7 about a certificate the JWK itself carries, and there it is enforced: see RFC7517-S4_7-R03.

Defers to: `RFC7517-S4_7-R03` (covered)

### `RFC7517-S4_6-R03` (MUST, section 4.6)

> The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the certificate MUST use TLS [RFC2818] [RFC5246]; the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].

This obligation is about the resource "x5u" names, and answering it requires fetching that resource: an HTTPS GET, a TLS trust store, and RFC 6125 identity validation. jwk performs no network I/O and holds "x5u" as a *url.URL it never dereferences, so no certificate is ever in hand to judge. That is a deliberate boundary rather than a gap -- a library that fetched URLs named in the documents it parses would be an SSRF primitive -- and it is the caller, holding the fetched certificate, who can apply this. The same sentence appears in section 4.7 about a certificate the JWK itself carries, and there it is enforced: see RFC7517-S4_7-R03.

Defers to: `RFC7517-S4_7-R03` (covered)

### `RFC7517-S4_6-R05` (MUST, section 4.6)

> If other members are present, the contents of those members MUST be semantically consistent with the related fields in the first certificate.

This obligation is about the resource "x5u" names, and answering it requires fetching that resource: an HTTPS GET, a TLS trust store, and RFC 6125 identity validation. jwk performs no network I/O and holds "x5u" as a *url.URL it never dereferences, so no certificate is ever in hand to judge. That is a deliberate boundary rather than a gap -- a library that fetched URLs named in the documents it parses would be an SSRF primitive -- and it is the caller, holding the fetched certificate, who can apply this. The same sentence appears in section 4.7 about a certificate the JWK itself carries, and there it is enforced: see RFC7517-S4_7-R03.

Defers to: `RFC7517-S4_7-R03` (covered)

### `RFC7517-S4_6-R06` (MUST, section 4.6)

> For instance, if the "use" member is present, then it MUST correspond to the usage that is specified in the certificate,

This obligation is about the resource "x5u" names, and answering it requires fetching that resource: an HTTPS GET, a TLS trust store, and RFC 6125 identity validation. jwk performs no network I/O and holds "x5u" as a *url.URL it never dereferences, so no certificate is ever in hand to judge. That is a deliberate boundary rather than a gap -- a library that fetched URLs named in the documents it parses would be an SSRF primitive -- and it is the caller, holding the fetched certificate, who can apply this. The same sentence appears in section 4.7 about a certificate the JWK itself carries, and there it is enforced: see RFC7517-S4_7-R03.

Defers to: `RFC7517-S4_7-R03` (covered)

### `RFC7517-S4_6-R07` (MUST, section 4.6)

> Similarly, if the "alg" member is present, it MUST correspond to the algorithm specified in the certificate.

This obligation is about the resource "x5u" names, and answering it requires fetching that resource: an HTTPS GET, a TLS trust store, and RFC 6125 identity validation. jwk performs no network I/O and holds "x5u" as a *url.URL it never dereferences, so no certificate is ever in hand to judge. That is a deliberate boundary rather than a gap -- a library that fetched URLs named in the documents it parses would be an SSRF primitive -- and it is the caller, holding the fetched certificate, who can apply this. The same sentence appears in section 4.7 about a certificate the JWK itself carries, and there it is enforced: see RFC7517-S4_7-R03.

Defers to: `RFC7517-S4_7-R03` (covered)

### `RFC7517-S4_8-R04` (MUST, section 4.8)

> If other members are present, the contents of those members MUST be semantically consistent with the related fields in the referenced certificate.

The certificate this sentence refers to is the one the thumbprint names, which a JWK generally does not carry. Every case where it does carry it is already covered, so a test here would restate one of those rather than add evidence: if the thumbprint names the first certificate, RFC7517-S4_7-R06 checks that certificate's consistency with "use"; if it names any later one, the document is already refused by RFC7517-S4_8-R01 / RFC7517-S4_9-R01, because a certificate further down the chain does not carry this key. Recorded as covered by construction rather than as an untested obligation.

Defers to: `RFC7517-S4_7-R06` (covered), `RFC7517-S4_8-R01` (covered), `RFC7517-S4_9-R01` (covered)

### `RFC7517-S4_9-R04` (MUST, section 4.9)

> If other members are present, the contents of those members MUST be semantically consistent with the related fields in the referenced certificate.

The certificate this sentence refers to is the one the thumbprint names, which a JWK generally does not carry. Every case where it does carry it is already covered, so a test here would restate one of those rather than add evidence: if the thumbprint names the first certificate, RFC7517-S4_7-R06 checks that certificate's consistency with "use"; if it names any later one, the document is already refused by RFC7517-S4_8-R01 / RFC7517-S4_9-R01, because a certificate further down the chain does not carry this key. Recorded as covered by construction rather than as an untested obligation.

Defers to: `RFC7517-S4_7-R06` (covered), `RFC7517-S4_8-R01` (covered), `RFC7517-S4_9-R01` (covered)

### `RFC7517-S5-R06` (MUST, section 5)

> The member names within a JWK Set MUST be unique; JWK Set parsers MUST either reject JWK Sets with duplicate member names or use a JSON parser that returns only the lexically last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].

jwk.KeySet is a struct with a single field, Keys, tagged "keys". A JWK Set this package composes has exactly one member name and no way to acquire a second, so the obligation is discharged by the API shape rather than by a code path a test could drive to failure. This requirement is the retrofitted producer half of the sentence whose parser half is RFC7517-S5-R03.

Defers to: `RFC7517-S5-R03` (covered)

### `RFC7517-S7-R01` (MUST, section 7)

> Access to JWKs containing non-public key material by parties without legitimate access to the non-public information MUST be prevented.

Deployment and access-control obligation on whoever transmits or stores a JWK, not a property of the encoding library: jwk serializes whatever key material the caller hands it and has no say in who can read those bytes afterwards, so no assertion over jwk.Key or jwk.KeySet could pass or fail this sentence. RFC7519-S12-R01 (privacy of claims) and RFC7517-S9_2-R01 (the same rule restated for private and symmetric keys) are the identical finding elsewhere; both are cited as parallels, and neither is the ground for this one.

Defers to: `RFC7517-S9_2-R01` (also excluded, reviewed), `RFC7519-S12-R01` (also excluded, reviewed)

### `RFC7517-S9_2-R01` (MUST, section 9.2)

> Private and symmetric keys MUST be protected from disclosure to unintended parties.

Protecting a private or symmetric key from disclosure is a property of how a deployment stores and transports that key, not of the library that encodes it: jwk serializes the key material it is handed and controls neither the medium it travels over nor the storage it lands in, so there is no jwk behavior an assertion could hold to this MUST. Section 7 states the same obligation in general terms and is excluded on this same reasoning at RFC7517-S7-R01, which is a parallel finding rather than the ground for this one.

Defers to: `RFC7517-S7-R01` (also excluded, reviewed)

## RFC7518 — JSON Web Algorithms (JWA)

### `RFC7518-S4_8-R01` (MUST, section 4.8)

> The PBES2 password input is an octet sequence; if the password to be used is represented as a text string rather than an octet sequence, the UTF-8 encoding of the text string MUST be used as the octet sequence.

jwa.PBES2 takes the password as []byte and never as a string, so there is no point at which this module chooses an encoding -- the requirement is discharged by the API shape rather than by a code path a test could exercise. That is the right division: Go source is UTF-8, so []byte(s) of a Go string is already the UTF-8 encoding this sentence asks for, and a library that accepted a string would be making the caller's normalization decisions for them. See RFC7518-S9-R01 for the preparation step that precedes this one. It is also not-testable, but on separate ground -- PRECIS needs Unicode tables this module will not carry -- so it is cited as a neighbouring finding and is not what this exclusion rests on.

Defers to: `RFC7518-S9-R01` (also excluded, reviewed)

### `RFC7518-S6_3_2_7-R02` (MUST, section 6.3.2.7)

> When three or more primes have been used, the number of array elements MUST be the number of primes used minus two.

This package refuses RSA keys of more than two primes in both directions, per the escape -R03 grants a consumer that does not support them, so it never produces an oth member whose length could be checked. Testing this would mean first implementing multi-prime support.

### `RFC7518-S6_3_2_7-R04` (MUST, section 6.3.2.7)

> Each array element MUST be an object with the following members.

Same reason as -R02: this package produces no oth member at all, having declined multi-prime keys outright. The consumer half of this requirement -- that a document using the object form is understood well enough to be refused rather than mis-parsed -- is what -R03 tests.

### `RFC7518-S8_4-R01` (MUST, section 8.4)

> In accordance with this rule, AES GCM MUST NOT be used with the same key value more than 2^32 times.

The bound is over the lifetime of a key, across every process that ever uses it. This module is stateless with respect to key material -- a key arrives as an argument and is forgotten when the call returns -- so there is nowhere to keep a counter and nothing to compare it against. Enforcing it would require the library to own key storage, which it deliberately does not. Recorded rather than quietly dropped: an application using "dir" or a long-lived A*GCMKW key needs to know the limit exists. The observable half of section 8.4 -- that this module never itself reuses an IV -- is asserted at RFC7518-S8_4-R02.

Defers to: `RFC7518-S8_4-R02` (covered)

### `RFC7518-S9-R01` (SHOULD, section 9)

> Passwords obtained from users are likely to require preparation and normalization to account for differences of octet sequences generated by different input devices, locales, etc. It is RECOMMENDED that applications perform the steps outlined in [PRECIS] to prepare a password supplied directly by a user before performing key derivation and encryption.

PRECIS OpaqueString preparation (RFC 7613) is a Unicode operation requiring the width-mapping, normalization and disallowed-code-point tables. This module has zero dependencies and the standard library does not provide them, so implementing it here would mean either taking a dependency or vendoring Unicode tables that go stale. More to the point, it is the wrong layer. jwa.PBES2 takes the password as []byte -- the API fact also recorded at RFC7518-S4_8-R01, and checkable in the signature rather than taken on that requirement's word -- so the caller has already decided what octets the password is, and preparing them afterwards would be second-guessing a decision already made with more context. The requirement is recorded as the application's rather than dropped, so the boundary stays visible to anyone reading the coverage report.

Defers to: `RFC7518-S4_8-R01` (also excluded, reviewed)

## RFC7519 — JSON Web Token (JWT)

### `RFC7519-S2-R01` (MUST, section 2)

> StringOrURI A JSON string value, with the additional requirement that while arbitrary string values MAY be used, any value containing a ":" character MUST be a URI [RFC3986].

This constrains the value an application chooses to put into iss/sub/aud, not a protocol behavior. jwt.WithIssuer/WithSubject/WithAudience accept any string and perform no URI validation (verified empirically), and RFC 7519 does not say a JWT library must validate this on the producer's behalf -- it is a producer obligation the same way well-formed JSON is. Nothing to assert without inventing a validation rule the spec does not require of implementations.

### `RFC7519-S3-R03` (MUST, section 4)

> The Claim Names within a JWT Claims Set MUST be unique; JWT parsers MUST either reject JWTs with duplicate Claim Names or use a JSON parser that returns only the lexically last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].

The claims set is assembled into a map[string]any by payload.MarshalJSON, and a Go map cannot hold the same key twice, so a duplicate Claim Name is not expressible. The one collision that could arise -- a private claim taking a registered claim's name -- is guarded twice: jwt.WithPrivateClaim rejects a registered name outright, and MarshalJSON copies the private claims in first so a registered claim always wins the name it owns. The obligation is therefore discharged by the API shape and by an explicit collision policy, not by a code path a test could drive to failure. This requirement is the retrofitted producer half of the sentence whose parser half is RFC7519-S3-R01.

Defers to: `RFC7519-S3-R01` (covered)

### `RFC7519-S4_1_2-R01` (MUST, section 4.1.2)

> The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique.

Uniqueness of a chosen identifier cannot be checked by a library with no knowledge of the issuer's namespace; sub is carried as an opaque string, matching this specification's silence on any syntax for it.

### `RFC7519-S4_1_3-R01` (MUST, section 4.1.3)

> Each principal intended to process the JWT MUST identify itself with a value in the audience claim.

Restates the same obligation R02 makes library-testable (rejection when the check fails). There is no separate library behavior for 'a principal identifies itself' beyond the aud-matching check R02 covers.

### `RFC7519-S4_1_3-R05` (MUST, section 4.1.3)

> The "aud" (audience) claim identifies the recipients that the JWT is intended for.

Not actually a requirement -- extractor false positive on a definitional sentence with no keyword. Removed from scope; kept as a record so the candidate is accounted for rather than silently dropped. (No MUST/SHOULD/MAY appears in this sentence.)

### `RFC7519-S4_1_7-R01` (MUST, section 4.1.7)

> The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object; if the application uses multiple issuers, collisions MUST be prevented among values produced by different issuers as well.

An application-level generation-quality obligation (effectively: use a UUID or equivalent). jwt.WithID accepts any caller-supplied string and this library has no jti-generation function of its own to hold to a collision-resistance standard.

### `RFC7519-S5_3-R01` (SHOULD, section 5.3)

> If such replicated claims are present, the application receiving them SHOULD verify that their values are identical, unless the application defines other specific processing rules for these claims.

Replicated claims are claims copied from the encrypted payload into an unencrypted header so an intermediary can read them without decrypting. This module never replicates a claim: header parameters and claims are separate types, jwt.Token writes no claim into any header, and jwt.Token.Decrypt reads claims only from the decrypted payload. Nor can a caller make it: header.Header has a field per registered parameter and no map for anything else, so jwt.Token.AddProtectedHeader -- the seam through which an application profile adds parameters of its own -- can write a key identifier and cannot write a claim by any name. So the condition -- "if such replicated claims are present" -- is never met by a token this module produces, and for one it receives the sentence addresses the application: only the application knows which claims it asked to have replicated and what its "other specific processing rules" are. A library that compared every header parameter against every same-named claim would be inventing a policy the RFC leaves open. Recorded rather than dropped, since an application doing header replication over this module needs to know the check is theirs to make.

### `RFC7519-S5_3-R02` (MAY, section 5.3)

> Other specifications MAY similarly register other names that are registered Claim Names as Header Parameter names, as needed.

Permission granted to future specification authors to extend the IANA registry, not an implementation requirement at all.

### `RFC7519-S10_1_1-R01` (SHOULD, section 10.1.1)

> Because a core goal of this specification is for the resulting representations to be compact, it is RECOMMENDED that the name be short -- that is, not to exceed 8 characters without a compelling reason to do so.

Registration-process guidance for whoever proposes new registered claim names to IANA; not a library behavior. (Excluded from `sections` along with the rest of Section 10, but individually enriched here since the extractor surfaced it as a standalone MUST/SHOULD candidate.)

### `RFC7519-S12-R01` (MUST, section 12)

> A JWT may contain privacy-sensitive information. When this is the case, measures MUST be taken to prevent disclosure of this information to unintended parties.

Deployment/transport-level obligation (use TLS, use encryption, or omit sensitive claims) that names no library mechanism. A JWS by design makes its payload readable to anyone holding the token -- that is not a defect this library could 'fix', it is what a signature (as opposed to encryption) provides. Analogous to the jku/x5u trust-decision requirements recorded not-testable in rfc-conformance/ir/rfc7515.json.

## RFC7638 — JSON Web Key (JWK) Thumbprint

### `RFC7638-S3_3-R02` (MUST, section 3.3)

> If the JWK key type uses members whose values are themselves JSON objects, then the members of those objects MUST likewise be lexicographically ordered.

The RFC states its own scope limit in the same sentence: "(As of the time of this writing, none are defined that do.)" None of the kty values RFC 7517/7518/8037 define -- EC, RSA, oct, OKP -- has a required member whose value is a JSON object, and jwk implements exactly those four. There is no required member to construct a test around; the condition this requirement guards is currently unreachable for any key type this package, or the RFCs it draws from, defines.

### `RFC7638-S3_3-R03` (MUST, section 3.3)

> If the JWK key type uses members whose values are JSON numbers, and if those numbers are integers, then they MUST be represented as a JSON number as defined in Section 6 of [RFC7159] without including a fraction part or exponent part. For instance, the value "1.024e3" MUST be represented as "1024".

Same scope limit as -R02, stated for this clause too: "(As of the time of this writing, none are defined that use JSON numbers.)" None of EC, RSA, oct, or OKP has a required member whose value is a JSON number -- every required member ("crv","kty","x","y","e","n","k") is a string. There is no required member this package could get wrong in the way the rule describes.

## RFC7797 — JSON Web Signature (JWS) Unencoded Payload Option

### `RFC7797-S3-R03` (MUST, section 3)

> If the JWS has multiple signatures and/or MACs, the "b64" Header Parameter value MUST be the same for all of them.

This module does not implement unencoded payloads at all. header.checkCritical returns ErrUnencodedPayload for any "b64" whose value is false, in both directions and whatever else the header carries -- the refusal depends on the parameter's value alone. RFC 7797 section 7 is why: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use "b64" with a "false" value", which is what makes this RFC an update to RFC 7519, and every object this module signs is a JWT whose payload is a claims set rather than arbitrary octets. This requirement governs how an unencoded payload behaves once permitted, a state this module never enters, so there is no code path to test.

### `RFC7797-S5_1-R01` (MUST, section 5.1)

> If an application uses a content encoding when representing the payload, then it MUST specify whether the signature or MAC is performed over the content-encoded representation or over the unencoded content.

This module does not implement unencoded payloads at all. header.checkCritical returns ErrUnencodedPayload for any "b64" whose value is false, in both directions and whatever else the header carries -- the refusal depends on the parameter's value alone. RFC 7797 section 7 is why: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use "b64" with a "false" value", which is what makes this RFC an update to RFC 7519, and every object this module signs is a JWT whose payload is a claims set rather than arbitrary octets. This requirement governs how an unencoded payload behaves once permitted, a state this module never enters, so there is no code path to test.

### `RFC7797-S5_2-R01` (MUST, section 5.2)

> When using the JWS Compact Serialization, unencoded non-detached payloads using period ('.') characters would cause parsing errors; such payloads MUST NOT be used with the JWS Compact Serialization.

This module does not implement unencoded payloads at all. header.checkCritical returns ErrUnencodedPayload for any "b64" whose value is false, in both directions and whatever else the header carries -- the refusal depends on the parameter's value alone. RFC 7797 section 7 is why: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use "b64" with a "false" value", which is what makes this RFC an update to RFC 7519, and every object this module signs is a JWT whose payload is a claims set rather than arbitrary octets. This requirement governs how an unencoded payload behaves once permitted, a state this module never enters, so there is no code path to test.

### `RFC7797-S5_2-R02` (MUST, section 5.2)

> Similarly, if a JWS using the JWS Compact Serialization and a non-detached payload is to be transmitted in a context that requires URL-safe characters, then the application MUST ensure that the payload contains only the URL-safe characters 'a'-'z', 'A'-'Z', '0'-'9', dash ('-'), underscore ('_'), and tilde ('~').

This module does not implement unencoded payloads at all. header.checkCritical returns ErrUnencodedPayload for any "b64" whose value is false, in both directions and whatever else the header carries -- the refusal depends on the parameter's value alone. RFC 7797 section 7 is why: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use "b64" with a "false" value", which is what makes this RFC an update to RFC 7519, and every object this module signs is a JWT whose payload is a claims set rather than arbitrary octets. This requirement governs how an unencoded payload behaves once permitted, a state this module never enters, so there is no code path to test.

### `RFC7797-S5_2-R03` (MAY, section 5.2)

> (those characters in the ranges %x20-2D and %x2F-7E) MAY be included in a non-detached payload using the JWS Compact Serialization, provided that the application can transmit the resulting JWS without modification.

This module does not implement unencoded payloads at all. header.checkCritical returns ErrUnencodedPayload for any "b64" whose value is false, in both directions and whatever else the header carries -- the refusal depends on the parameter's value alone. RFC 7797 section 7 is why: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use "b64" with a "false" value", which is what makes this RFC an update to RFC 7519, and every object this module signs is a JWT whose payload is a claims set rather than arbitrary octets. This requirement governs how an unencoded payload behaves once permitted, a state this module never enters, so there is no code path to test.

### `RFC7797-S5_3-R01` (MUST, section 5.3)

> Unassigned Unicode code point values MUST NOT be used to represent the payload.

This module does not implement unencoded payloads at all. header.checkCritical returns ErrUnencodedPayload for any "b64" whose value is false, in both directions and whatever else the header carries -- the refusal depends on the parameter's value alone. RFC 7797 section 7 is why: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use "b64" with a "false" value", which is what makes this RFC an update to RFC 7519, and every object this module signs is a JWT whose payload is a claims set rather than arbitrary octets. This requirement governs how an unencoded payload behaves once permitted, a state this module never enters, so there is no code path to test.

### `RFC7797-S7-R01` (SHOULD, section 7)

> It is NOT RECOMMENDED that this parameter value be dynamically varied with different payloads in the same application context.

This module does not implement unencoded payloads at all. header.checkCritical returns ErrUnencodedPayload for any "b64" whose value is false, in both directions and whatever else the header carries -- the refusal depends on the parameter's value alone. RFC 7797 section 7 is why: "For interoperability reasons, JSON Web Tokens [JWT] MUST NOT use "b64" with a "false" value", which is what makes this RFC an update to RFC 7519, and every object this module signs is a JWT whose payload is a claims set rather than arbitrary octets. This requirement governs how an unencoded payload behaves once permitted, a state this module never enters, so there is no code path to test.

## RFC7800 — Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)

### `RFC7800-S3_5-R01` (MUST, section 3.5)

> If there are multiple keys in the referenced JWK Set document, a "kid" member MUST also be included with the referenced key's JWK also containing the same "kid" value.

This package never dereferences "cnf"."jku" -- Confirmation.KeySetURL holds the parsed *url.URL, and no HTTP fetch of any kind is performed. The only net/... import anywhere in the non-test source tree is net/url, a parser, and nothing holds a transport: conformance/rfc8725's TestJKUAndX5UAreNeverDereferenced walks the source and fails on net/http, net/rpc, net/smtp or net/mail appearing in any of it. The condition is a fact about the referenced document -- how many keys it holds, and what "kid" the intended one carries -- and that document is never retrieved, so the condition can never be evaluated here. What this package does do is carry "kid" beside "jku" without refusing the pair, which RFC7800-S3_1-R02's oracle asserts: "kid" is deliberately outside the mutually exclusive set precisely so that this requirement can be satisfied.

Defers to: `RFC7800-S3_1-R02` (covered)

### `RFC7800-S3_5-R02` (MUST, section 3.5)

> The protocol used to acquire the resource MUST provide integrity protection.

This package never dereferences "cnf"."jku" -- Confirmation.KeySetURL holds the parsed *url.URL, and no HTTP fetch of any kind is performed. The only net/... import anywhere in the non-test source tree is net/url, a parser, and nothing holds a transport: conformance/rfc8725's TestJKUAndX5UAreNeverDereferenced walks the source and fails on net/http, net/rpc, net/smtp or net/mail appearing in any of it. There is no fetch code path for this MUST's integrity-protection obligation to bind to. The identical position is on record for the JOSE header's "jku" and "x5u" at RFC7515-S4_1_2-R01 and RFC7515-S4_1_5-R01; those are parallels, and this exclusion rests on the source-tree check named above rather than on either of them.

Defers to: `RFC7515-S4_1_2-R01` (also excluded, reviewed), `RFC7515-S4_1_5-R01` (also excluded, reviewed)

### `RFC7800-S3_5-R03` (MUST, section 3.5)

> An HTTP GET request to retrieve the JWK Set MUST use TLS [RFC5246] and the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].

This package never dereferences "cnf"."jku" -- Confirmation.KeySetURL holds the parsed *url.URL, and no HTTP fetch of any kind is performed. The only net/... import anywhere in the non-test source tree is net/url, a parser, and nothing holds a transport: conformance/rfc8725's TestJKUAndX5UAreNeverDereferenced walks the source and fails on net/http, net/rpc, net/smtp or net/mail appearing in any of it. Both obligations are about an HTTP GET this package never issues. A caller who dereferences the URL themselves owns them, along with the choice of client and trust store that makes them meaningful -- which is the same reason RFC 5280 path validation stays out at RFC7515-S4_1_6-R01b -- a parallel finding cited for context, while this exclusion rests on the source-tree check named above.

Defers to: `RFC7515-S4_1_6-R01b` (also excluded, reviewed)

### `RFC7800-S6_2_1-R01` (SHOULD, section 6.2.1)

> Because a core goal of this specification is for the resulting representations to be compact, it is RECOMMENDED that the name be short -- not to exceed eight characters without a compelling reason to do so.

Guidance to whoever registers a confirmation method with IANA, not to software that reads one. This module registers nothing; it implements the four members section 3 defines and RFC 9449's "jkt", every one of which was named by its own document. No input to this package can satisfy or violate it.

## RFC8037 — CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)

### `RFC8037-S4-R02` (SHOULD, section 4)

> The nominal security strengths of X25519 and X448 are ~126 and ~223 bits. Therefore, using 256-bit symmetric encryption (especially key wrapping and encryption) with X448 is RECOMMENDED.

X448 is not implemented. Of RFC 8037 section 5's four OKP subtypes this package implements two, Ed25519 for signing and X25519 for key agreement; parseOctetKeyPair allowlists exactly those two and returns ErrUnsupportedCurve for every other "crv", Ed448 and X448 among them, because the standard library has no crypto/ed448 and its crypto/ecdh offers X25519 as its only non-NIST curve. This recommendation is about which symmetric strength to pair with X448, so with X448 absent there is no code path on which it can be honoured or violated. Kept in the IR rather than dropped so that adding X448 later starts with the obligation already recorded.

## RFC8725 — JSON Web Token Best Current Practices

### `RFC8725-S3_2-R02` (MUST, section 3.2)

> Therefore, applications MUST only allow the use of cryptographically current algorithms that meet the security requirements of the application. This set will vary over time as new algorithms are introduced and existing algorithms are deprecated due to discovered cryptographic weaknesses. Applications MUST therefore be designed to enable cryptographic agility.

"Cryptographically current" is a value judgement about specific algorithms' present-day safety, which shifts over time and is not something a fixed conformance test can assert as pass/fail. The obligation's bearer is explicitly "applications", not the library. What the library can and does provide — a caller-parameterized algorithm allowlist rather than a hardcoded one, which is the mechanism that makes cryptographic agility possible at all — is already covered by RFC8725-S3_1-R01a; testing it twice under two ids would not add coverage.

Defers to: `RFC8725-S3_1-R01a` (covered)

### `RFC8725-S3_9-R01` (MUST, section 3.9)

> If the same issuer can issue JWTs that are intended for use by more than one relying party or application, the JWT MUST contain an "aud" (audience) claim that can be used to determine whether the JWT is being used by an intended party or was substituted by an attacker at an unintended party.

Whether "the same issuer can issue JWTs intended for more than one relying party" is a fact about a deployment's issuance topology, not something a general-purpose library can know or assert. The library does support setting an "aud" claim (jwt.WithAudience) so an issuer can comply, but that capability is exercised as setup for RFC8725-S3_9-R02's test, not as independent coverage of this issuer-side policy MUST.

Defers to: `RFC8725-S3_9-R02` (covered)

## RFC9964 — ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)

### `RFC9964-S7_3-R03` (MUST, section 7.3)

> However, when the priv parameter is expanded using KeyGen_internal, the skEncode and skDecode algorithms MUST be used.

The obligation is on the expanded private key representation, and this module has no surface that holds one. RFC 9964 Section 4 makes "priv" the seed alone, so the expanded key never appears in a JWK, never crosses this module's API, and is never written or read by it: the seed goes to mldsa.NewPrivateKey and the expanded key stays inside crypto/mldsa, which is the FIPS 140-3 validated implementation this sentence is addressed to. There is no input this module accepts and no output it produces that would differ between an implementation that used skEncode and skDecode and one that did not. Demonstrating the property needs the internals of the standard library's ML-DSA, not a JOSE-level assertion.
