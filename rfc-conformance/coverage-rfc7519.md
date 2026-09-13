# Requirement coverage: RFC7519

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 23 | 23 | 100% |
| SHOULD | 7 | 7 | 100% |
| MAY | 17 | 17 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC7519-S2-R01` (not-testable)
- `RFC7519-S3-R03` (not-testable)
- `RFC7519-S4_1_2-R01` (not-testable)
- `RFC7519-S4_1_3-R01` (not-testable)
- `RFC7519-S4_1_3-R05` (not-testable)
- `RFC7519-S4_1_7-R01` (not-testable)
- `RFC7519-S5_3-R01` (not-testable)
- `RFC7519-S5_3-R02` (not-testable)
- `RFC7519-S10_1_1-R01` (not-testable)
- `RFC7519-S12-R01` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7519-S2-R01` | MUST | not-testable | -- |
| `RFC7519-S3-R01` | MUST | unit | TestDuplicateAndUnrecognizedClaimNames (rfc7519/rfc7519_test.go) |
| `RFC7519-S3-R03` | MUST | not-testable | -- |
| `RFC7519-S3-R02` | MUST | unit | TestDuplicateAndUnrecognizedClaimNames (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_1-R01` | MAY | unit | TestAllRegisteredClaimsAreOptional (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_2-R01` | MUST | not-testable | TestSubjectUniquenessIsAnApplicationObligation (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_2-R02` | MAY | unit | TestAllRegisteredClaimsAreOptional (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_3-R01` | MUST | not-testable | -- |
| `RFC7519-S4_1_3-R02` | MUST | unit | TestAudienceMismatchIsRejected (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_3-R03` | MAY | unit | TestAudienceAcceptsBothArrayAndBareStringForms (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_3-R04` | MAY | unit | TestAllRegisteredClaimsAreOptional (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_3-R05` | MUST | not-testable | -- |
| `RFC7519-S4_1_4-R01` | MUST | unit | TestExpirationTimeIsEnforced (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_4-R02` | MUST | unit | TestExpirationTimeIsEnforced (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_4-R03` | MAY | unit | TestLeewayToleratesClockSkew (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_4-R04` | MUST | unit | TestNumericDateClaimsRejectNonNumericValues (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_4-R05` | MAY | unit | TestAllRegisteredClaimsAreOptional (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_5-R01` | MUST | unit | TestNotBeforeIsEnforced (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_5-R02` | MUST | unit | TestNotBeforeIsEnforced (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_5-R03` | MAY | unit | TestLeewayToleratesClockSkew (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_5-R04` | MUST | unit | TestNumericDateClaimsRejectNonNumericValues (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_5-R05` | MAY | unit | TestAllRegisteredClaimsAreOptional (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_6-R01` | MUST | unit | TestNumericDateClaimsRejectNonNumericValues (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_6-R02` | MAY | unit | TestAllRegisteredClaimsAreOptional (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_6-R03` | MUST | unit | TestFutureIssuedAtIsNotRejected (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_7-R01` | MUST | not-testable | TestJTICollisionResistanceIsAnApplicationObligation (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_1_7-R02` | MAY | unit | TestAllRegisteredClaimsAreOptional (rfc7519/rfc7519_test.go) |
| `RFC7519-S4_3-R01` | MAY | unit | TestPrivateClaimNamesRoundTrip (rfc7519/rfc7519_test.go) |
| `RFC7519-S5_1-R01` | SHOULD | unit | TestSignedTokenAlwaysDeclaresTypJWT (rfc7519/rfc7519_test.go) |
| `RFC7519-S5_1-R02` | SHOULD | unit | TestSignedTokenAlwaysDeclaresTypJWT (rfc7519/rfc7519_test.go) |
| `RFC7519-S5_1-R03` | MAY | unit | TestTypAbsenceIsTolerated (rfc7519/rfc7519_test.go) |
| `RFC7519-S5_2-R01` | SHOULD | unit | TestOrdinaryTokenNeverSetsCty (rfc7519/rfc7519_test.go) |
| `RFC7519-S5_2-R02` | MUST | unit | TestNestedJWTSetsContentTypeJWT (rfc7519/encryption_test.go) |
| `RFC7519-S5_2-R03` | SHOULD | unit | TestNestedContentTypeIsUppercase (rfc7519/encryption_test.go), TestNestedContentTypeIsReadCaseInsensitively (rfc7519/encryption_test.go) |
| `RFC7519-S5_3-R01` | SHOULD | not-testable | -- |
| `RFC7519-S5_3-R02` | MAY | not-testable | -- |
| `RFC7519-S6-R01` | MAY | unit | TestUnsecuredJWTUsesNoneAlgorithmAndEmptySignature (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_1-R01` | MUST | unit | TestSignedTokenIsAWellFormedJWS (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_1-R02` | MUST | unit | TestSignedTokenIsAWellFormedJWS (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_1-R03` | MUST | unit | TestEncryptedJWTFollowsTheJWESteps (rfc7519/encryption_test.go) |
| `RFC7519-S7_2-R01` | MUST | unit | TestUnacceptableAlgorithmIsRejectedEvenIfSignatureValid (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_2-R02` | SHOULD | unit | TestUnacceptableAlgorithmIsRejectedEvenIfSignatureValid (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_2-R03` | MUST | unit | TestHeaderSegmentMustDecodeToAJSONObject (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_2-R04` | MUST | unit | TestPayloadSegmentMustDecodeToAJSONObject (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_2-R05` | MUST | unit | TestUnrecognizedHeaderParameterIsIgnoredNotRejected (rfc7519/rfc7519_test.go) |
| `RFC7519-S7_3-R01` | MUST | unit | TestNestedContentTypeIsReadCaseInsensitively (rfc7519/encryption_test.go), TestStringClaimComparisonsAreCaseSensitive (rfc7519/rfc7519_test.go) |
| `RFC7519-S8-R01` | MUST | unit | TestBaselineAlgorithmsHS256AndNoneAreImplemented (rfc7519/rfc7519_test.go) |
| `RFC7519-S8-R02` | SHOULD | unit | TestRecommendedAlgorithmsRS256AndES256AreImplemented (rfc7519/rfc7519_test.go) |
| `RFC7519-S8-R03` | MAY | unit | TestOptionalSignatureAlgorithms (rfc7519/rfc7519_test.go) |
| `RFC7519-S8-R04` | MAY | unit | TestEncryptedJWTsAreSupported (rfc7519/encryption_test.go) |
| `RFC7519-S8-R05` | MUST | unit | TestRequiredEncryptionAlgorithms (rfc7519/encryption_test.go) |
| `RFC7519-S8-R06` | SHOULD | unit | TestRecommendedEncryptionAlgorithms (rfc7519/encryption_test.go) |
| `RFC7519-S8-R07` | MAY | unit | TestOptionalEncryptionAlgorithms (rfc7519/encryption_test.go) |
| `RFC7519-S8-R08` | MAY | unit | TestNestedJWTsAreSupported (rfc7519/encryption_test.go) |
| `RFC7519-S10_1_1-R01` | SHOULD | not-testable | -- |
| `RFC7519-S12-R01` | MUST | not-testable | -- |
| `RFC7519-S6-R02` | MUST | unit | TestUnsecuredJWTUsesNoneAlgorithmAndEmptySignature (rfc7519/rfc7519_test.go) |
