# Requirement coverage: RFC8725

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 10 | 10 | 100% |
| SHOULD | 8 | 8 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC8725-S3_2-R02` (not-testable)
- `RFC8725-S3_9-R01` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC8725-S3_1-R01a` | MUST | unit | TestVerificationHonorsCallerConfiguredAlgorithmAllowlist (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_1-R01b` | MUST | unit | TestVerificationHonorsCallerConfiguredAlgorithmAllowlist (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_1-R02` | MUST | unit | TestKeyConfusionAttackFailsClosed (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_1-R03` | MUST | unit | TestKeySelectionEnforcesSingleAlgorithmBinding (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_10-R01` | SHOULD | unit | TestTheNetworkingPackageCannotSeeAToken (rfc8725/rfc8725_test.go), TestAnUnknownKeyCausesOneKeyRefreshAtMost (rfc8725/rfc8725_test.go), TestJKUAndX5UAreNeverDereferenced (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_11-R01` | SHOULD | unit | TestExplicitTypingRoundTrips (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_11-R04` | MUST | unit | TestNestedJWTCarriesTheExplicitTypeInside (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_11-R05` | SHOULD | unit | TestExplicitTypingRoundTrips (rfc8725/rfc8725_test.go), TestExplicitTypingIsEnforcedOnTheReadPath (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_2-R02` | MUST | not-testable | -- |
| `RFC8725-S3_2-R04` | SHOULD | unit | TestNoneAlgorithmRequiresExplicitOptIn (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_2-R05` | SHOULD | unit | TestNoneAlgorithmRequiresExplicitOptIn (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_2-R06` | SHOULD | unit | TestRSAPKCS1V15IsAvoided (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_2-R07` | SHOULD | unit | TestECDSASigningIsDeterministic (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_3-R01` | MUST | unit | TestSignatureTamperCausesRejection (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_3-R02` | MUST | unit | TestNestedJWTValidatesBothOperations (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_4-R01` | MUST | unit | TestECDHInputsAreValidated (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_6-R01` | SHOULD | unit | TestCompressionIsNotDoneBeforeEncryption (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_7-R01` | MUST | unit | TestUTF8OnlyEncoding (rfc8725/rfc8725_test.go) |
| `RFC8725-S3_9-R01` | MUST | not-testable | -- |
| `RFC8725-S3_9-R02` | MUST | unit | TestAudienceValidation (rfc8725/rfc8725_test.go) |
