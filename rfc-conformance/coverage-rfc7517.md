# Requirement coverage: RFC7517

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 20 | 20 | 100% |
| SHOULD | 1 | 1 | 100% |
| MAY | 16 | 16 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC7517-S4-R04` (not-testable)
- `RFC7517-S4_3-R04` (not-testable)
- `RFC7517-S4_3-R05` (not-testable)
- `RFC7517-S4_3-R07` (not-testable)
- `RFC7517-S4_5-R01` (not-testable)
- `RFC7517-S4_6-R01` (not-testable)
- `RFC7517-S4_6-R02` (not-testable)
- `RFC7517-S4_6-R03` (not-testable)
- `RFC7517-S4_6-R05` (not-testable)
- `RFC7517-S4_6-R06` (not-testable)
- `RFC7517-S4_6-R07` (not-testable)
- `RFC7517-S4_8-R04` (not-testable)
- `RFC7517-S4_9-R04` (not-testable)
- `RFC7517-S5-R06` (not-testable)
- `RFC7517-S7-R01` (not-testable)
- `RFC7517-S9_2-R01` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7517-S2-R01` | MUST | unit | TestJWKSetKeysMemberIsAlwaysPresent (rfc7517/rfc7517_test.go) |
| `RFC7517-S4-R01` | MAY | unit | TestJWKToleratesWhitespaceAroundValuesAndStructuralCharacters (rfc7517/rfc7517_test.go) |
| `RFC7517-S4-R02` | MUST | unit | TestJWKDuplicateMemberNameIsRejected (rfc7517/rfc7517_test.go) |
| `RFC7517-S4-R04` | MUST | not-testable | -- |
| `RFC7517-S4-R03` | MUST | unit | TestJWKIgnoresAnUnrecognizedMember (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_1-R01` | MUST | unit | TestKeyTypeIsAlwaysPresent (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_2-R01` | MAY | unit | TestPublicKeyUseAcceptsValuesBeyondSigAndEnc (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_2-R02` | MAY | unit | TestPublicKeyUseIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_3-R01` | MAY | unit | TestKeyOperationsAcceptsValuesBeyondTheEightRegistered (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_3-R02` | MUST | unit | TestDuplicateKeyOperationsAreRejected (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_3-R03` | MAY | unit | TestKeyOperationsIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_3-R04` | SHOULD | not-testable | -- |
| `RFC7517-S4_3-R05` | SHOULD | not-testable | -- |
| `RFC7517-S4_3-R06` | MUST | unit | TestInconsistentPublicKeyUseIsRejected (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_3-R07` | SHOULD | not-testable | -- |
| `RFC7517-S4_4-R01` | MAY | unit | TestAlgorithmIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_5-R01` | SHOULD | not-testable | -- |
| `RFC7517-S4_5-R02` | MAY | unit | TestKeyIDIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_6-R01` | MUST | not-testable | -- |
| `RFC7517-S4_6-R02` | MUST | not-testable | -- |
| `RFC7517-S4_6-R03` | MUST | not-testable | -- |
| `RFC7517-S4_6-R04` | MAY | unit | TestX509URLIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_6-R05` | MUST | not-testable | -- |
| `RFC7517-S4_6-R06` | MUST | not-testable | -- |
| `RFC7517-S4_6-R07` | MUST | not-testable | -- |
| `RFC7517-S4_7-R01` | MUST | unit | TestTheKeysCertificateMustComeFirst (rfc7517/certificates_test.go) |
| `RFC7517-S4_7-R02` | MAY | unit | TestX509CertificateChainPreservesOrderAcrossMultipleCertificates (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_7-R03` | MUST | unit | TestACertificateForAnotherKeyIsRefused (rfc7517/certificates_test.go) |
| `RFC7517-S4_7-R04` | MAY | unit | TestX509CertificateChainIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_7-R05` | MAY | unit | TestX509CertificateChainCoexistsWithOtherOptionalMembers (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_7-R06` | MUST | unit | TestUseMustCorrespondToTheCertificate (rfc7517/certificates_test.go) |
| `RFC7517-S4_7-R07` | MUST | unit | TestX509CertificateChainUsesStandardBase64NotURLSafeAlphabet (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_8-R01` | MUST | unit | TestAThumbprintNamingACarriedCertificateMustNameThisKeys (rfc7517/certificates_test.go) |
| `RFC7517-S4_8-R02` | MAY | unit | TestX509SHA1ThumbprintIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_8-R03` | MAY | unit | TestX509SHA1ThumbprintCoexistsWithOtherOptionalMembers (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_8-R04` | MUST | not-testable | -- |
| `RFC7517-S4_8-R05` | MUST | unit | TestAThumbprintIsADigestOfTheStatedLength (rfc7517/certificates_test.go) |
| `RFC7517-S4_9-R01` | MUST | unit | TestAThumbprintNamingACarriedCertificateMustNameThisKeys (rfc7517/certificates_test.go) |
| `RFC7517-S4_9-R02` | MAY | unit | TestX509SHA256ThumbprintIsOptional (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_9-R03` | MAY | unit | TestX509SHA256ThumbprintCoexistsWithOtherOptionalMembers (rfc7517/rfc7517_test.go) |
| `RFC7517-S4_9-R04` | MUST | not-testable | -- |
| `RFC7517-S4_9-R05` | MUST | unit | TestAThumbprintIsADigestOfTheStatedLength (rfc7517/certificates_test.go) |
| `RFC7517-S5-R01` | MUST | unit | TestJWKSetKeysMemberIsAlwaysPresent (rfc7517/rfc7517_test.go) |
| `RFC7517-S5-R02` | MAY | unit | TestJWKSetToleratesWhitespace (rfc7517/rfc7517_test.go) |
| `RFC7517-S5-R03` | MUST | unit | TestJWKSetDuplicateMemberNameIsRejected (rfc7517/rfc7517_test.go) |
| `RFC7517-S5-R06` | MUST | not-testable | -- |
| `RFC7517-S5-R04` | MUST | unit | TestJWKSetIgnoresAnUnrecognizedMember (rfc7517/rfc7517_test.go) |
| `RFC7517-S5-R05` | SHOULD | unit | TestJWKSetIgnoresUnusableKeys (rfc7517/rfc7517_test.go) |
| `RFC7517-S6-R01` | MUST | unit | TestKeySetSelectionComparesKeyIDCaseSensitively (rfc7517/rfc7517_test.go) |
| `RFC7517-S7-R01` | MUST | not-testable | -- |
| `RFC7517-S7-R02` | MUST | unit | TestEncryptedJWKUsesTheContentType (rfc7517/rfc7517_test.go) |
| `RFC7517-S7-R03` | MUST | unit | TestEncryptedJWKSetUsesTheContentType (rfc7517/rfc7517_test.go) |
| `RFC7517-S9_2-R01` | MUST | not-testable | -- |
