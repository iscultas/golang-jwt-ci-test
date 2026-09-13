# Requirement coverage: RFC7638

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 10 | 10 | 100% |
| MAY | 1 | 1 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC7638-S3_3-R02` (not-testable)
- `RFC7638-S3_3-R03` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7638-S3-R01a` | MUST | unit | TestOptionalMembersDoNotAffectTheThumbprint (rfc7638/rfc7638_test.go) |
| `RFC7638-S3-R01b` | MUST | unit | TestWorkedExampleThumbprintMatchesTheRFC (rfc7638/rfc7638_test.go) |
| `RFC7638-S3-R01c` | MUST | unit | TestWorkedExampleThumbprintMatchesTheRFC (rfc7638/rfc7638_test.go) |
| `RFC7638-S3-R02` | MUST | unit | TestWorkedExampleThumbprintMatchesTheRFC (rfc7638/rfc7638_test.go) |
| `RFC7638-S3_2-R01` | MUST | unit | TestRequiredMembersForEllipticCurveKey (rfc7638/rfc7638_test.go) |
| `RFC7638-S3_2-R02` | MUST | unit | TestRequiredMembersForRSAKey (rfc7638/rfc7638_test.go) |
| `RFC7638-S3_2-R03` | MUST | unit | TestRequiredMembersForSymmetricKey (rfc7638/rfc7638_test.go) |
| `RFC7638-S3_2_1-R01` | MUST | unit | TestPrivateKeyThumbprintEqualsPublicKeyThumbprint (rfc7638/rfc7638_test.go) |
| `RFC7638-S3_3-R01` | MUST | unit | TestMemberValuesContainNoEscapedCharacters (rfc7638/rfc7638_test.go) |
| `RFC7638-S3_3-R02` | MUST | not-testable | -- |
| `RFC7638-S3_3-R03` | MUST | not-testable | -- |
| `RFC7638-S3_4-R01` | MUST | unit | TestHashFunctionIsCallerSelected (rfc7638/rfc7638_test.go) |
| `RFC7638-S3_5-R01` | MAY | unit | TestThumbprintFromNativeKeyMaterialMatchesFromDecodedJWK (rfc7638/rfc7638_test.go) |
