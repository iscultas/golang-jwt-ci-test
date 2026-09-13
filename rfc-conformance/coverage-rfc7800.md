# Requirement coverage: RFC7800

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 6 | 6 | 100% |
| MAY | 2 | 2 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC7800-S3_5-R01` (not-testable)
- `RFC7800-S3_5-R02` (not-testable)
- `RFC7800-S3_5-R03` (not-testable)
- `RFC7800-S6_2_1-R01` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7800-S3-R00` | MUST | unit | TestTheConfirmationClaimIsAJSONObject (rfc7800/rfc7800_test.go) |
| `RFC7800-S3-R01` | MUST | unit | TestConfirmationRequiresAPresenter (rfc7800/rfc7800_test.go) |
| `RFC7800-S3_1-R01` | MUST | unit | TestUnknownConfirmationMembersAreIgnored (rfc7800/rfc7800_test.go) |
| `RFC7800-S3_1-R02` | MUST | unit | TestConfirmationNamesOneKey (rfc7800/rfc7800_test.go) |
| `RFC7800-S3_2-R01a` | MUST | unit | TestTheConfirmationKeyIsAWellFormedJWK (rfc7800/rfc7800_test.go) |
| `RFC7800-S3_2-R01b` | MAY | unit | TestTheConfirmationKeyMayCarryOptionalMembers (rfc7800/rfc7800_test.go) |
| `RFC7800-S3_2-R02` | MAY | unit | TestASymmetricConfirmationKeyNeedsAnEncryptedToken (rfc7800/rfc7800_test.go) |
| `RFC7800-S3_2-R03` | MUST | unit | TestASymmetricConfirmationKeyNeedsAnEncryptedToken (rfc7800/rfc7800_test.go) |
| `RFC7800-S3_5-R01` | MUST | not-testable | -- |
| `RFC7800-S3_5-R02` | MUST | not-testable | -- |
| `RFC7800-S3_5-R03` | MUST | not-testable | -- |
| `RFC7800-S6_2_1-R01` | SHOULD | not-testable | -- |
