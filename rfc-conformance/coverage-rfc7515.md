# Requirement coverage: RFC7515

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 33 | 33 | 100% |
| SHOULD | 2 | 2 | 100% |
| MAY | 12 | 12 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC7515-S2-R01` (not-testable)
- `RFC7515-S3_2-R02` (not-testable)
- `RFC7515-S4-R05` (not-testable)
- `RFC7515-S4-R02` (not-testable)
- `RFC7515-S4-R03` (not-testable)
- `RFC7515-S4_1_2-R01` (not-testable)
- `RFC7515-S4_1_5-R01` (not-testable)
- `RFC7515-S4_1_6-R01b` (not-testable)
- `RFC7515-S4_1_9-R02` (not-testable)
- `RFC7515-S4_1_9-R03` (not-testable)
- `RFC7515-S4_1_11-R02d` (not-testable)
- `RFC7515-S6-R01` (not-testable)
- `RFC7515-S6-R02` (not-testable)
- `RFC7515-S8-R01` (not-testable)
- `RFC7515-S10_12-R02` (not-testable)
- `RFC7515-S10_12-R06` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7515-S2-R01` | MAY | not-testable | -- |
| `RFC7515-S3-R01` | MAY | unit | TestJSONSerializationToleratesInsignificantWhitespace (rfc7515/rfc7515_test.go) |
| `RFC7515-S3_2-R01` | MUST | unit | TestJSONSerializationRequiresAtLeastOneHeaderMember (rfc7515/rfc7515_test.go) |
| `RFC7515-S3_2-R02` | MAY | not-testable | -- |
| `RFC7515-S4-R01` | MUST | unit | TestDuplicateHeaderParameterNameIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S4-R05` | MUST | not-testable | -- |
| `RFC7515-S4-R02` | MUST | not-testable | -- |
| `RFC7515-S4-R03` | MUST | not-testable | -- |
| `RFC7515-S4-R04` | MUST | unit | TestUnknownHeaderParameterIsIgnored (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_1-R01` | MUST | unit | TestAlgorithmHeaderParameterRequired (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_2-R01` | MUST | not-testable | -- |
| `RFC7515-S4_1_2-R04` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_3-R01` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_3-R02` | MUST | unit | TestTheJWKHeaderParameterIsThePublicSigningKey (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_4-R01` | MUST | unit | TestKeyIDIsCaseSensitive (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_4-R02` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go), TestAKeyIDIsOptionalEvenAgainstASetOfSeveralKeys (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_5-R01` | MUST | not-testable | -- |
| `RFC7515-S4_1_5-R05` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_6-R01a` | MUST | unit | TestSigningRefusesACertificateForAnotherKey (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_6-R01b` | MUST | not-testable | -- |
| `RFC7515-S4_1_6-R04` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_7-R01` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_8-R01` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_9-R01` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_9-R02` | SHOULD | not-testable | -- |
| `RFC7515-S4_1_9-R03` | MUST | not-testable | -- |
| `RFC7515-S4_1_10-R01` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_10-R03` | MUST | unit | TestContentTypeIsReadAsAMediaType (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R01` | MUST | unit | TestCriticalHeaderParameterIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R02a` | MUST | unit | TestTheCriticalListIsWellFormed (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R02b` | MUST | unit | TestTheCriticalListIsWellFormed (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R02c` | MUST | unit | TestTheCriticalListIsWellFormed (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R02d` | MUST | not-testable | -- |
| `RFC7515-S4_1_11-R04` | MAY | unit | TestCriticalHeaderParameterIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R05` | MUST | unit | TestCriticalHeaderParameterIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R06` | MAY | unit | TestOptionalHeaderParametersMayBeOmitted (rfc7515/rfc7515_test.go) |
| `RFC7515-S4_1_11-R07` | MUST | unit | TestCriticalHeaderParameterIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S5_1-R01` | MUST | unit | TestSigningAlwaysSetsAccurateAlgorithm (rfc7515/rfc7515_test.go) |
| `RFC7515-S5_2-R01` | MUST | unit | TestAtLeastOneSignatureMustValidate (rfc7515/rfc7515_test.go) |
| `RFC7515-S5_2-R02` | MUST | unit | TestDuplicateHeaderParameterAcrossProtectedAndUnprotectedIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S5_2-R03` | MUST | unit | TestValidationRequiresSuccessfulSignatureCheck (rfc7515/rfc7515_test.go) |
| `RFC7515-S5_2-R05` | SHOULD | unit | TestAlgorithmAcceptabilityIsCallerConfigurable (rfc7515/rfc7515_test.go) |
| `RFC7515-S5_3-R01` | MUST | unit | TestStringComparisonIsCaseSensitiveAndEscapeNormalized (rfc7515/rfc7515_test.go) |
| `RFC7515-S6-R01` | MUST | not-testable | -- |
| `RFC7515-S6-R02` | SHOULD | not-testable | -- |
| `RFC7515-S7_2_1-R01` | MUST | unit | TestGeneralJSONSerializationMemberPresence (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_1-R02` | MUST | unit | TestSignaturesMemberMustBeArray (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_1-R03` | MUST | unit | TestGeneralJSONSerializationMemberPresence (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_1-R04` | MUST | unit | TestUnprotectedHeaderMemberPresentOnlyWhenNonEmpty (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_1-R05` | MUST | unit | TestGeneralJSONSerializationMemberPresence (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_1-R06` | MUST | unit | TestJSONSerializationRequiresAtLeastOneHeaderMember (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_1-R07` | MUST | unit | TestUnknownMemberInSignatureObjectIsIgnored (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_1-R08` | MUST | unit | TestDuplicateHeaderParameterAcrossProtectedAndUnprotectedIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S7_2_2-R01` | MUST | unit | TestMixedFlattenedAndGeneralSyntaxIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S8-R01` | MUST | not-testable | -- |
| `RFC7515-S10_6-R01` | MUST | unit | TestAlgorithmConfusionAcrossHashSizesFailsClosed (rfc7515/rfc7515_test.go) |
| `RFC7515-S10_9-R01` | MUST | static | TestHMACComparisonUsesConstantTimeEquality (rfc7515/rfc7515_test.go) |
| `RFC7515-S10_12-R01` | MUST | unit | TestMalformedJSONIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S10_12-R02` | SHOULD | not-testable | -- |
| `RFC7515-S10_12-R03` | MUST | unit | TestDuplicateHeaderParameterNameIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S10_12-R06` | MUST | not-testable | -- |
| `RFC7515-S10_12-R05` | MUST | unit | TestTrailingDataAfterValidJSONIsRejected (rfc7515/rfc7515_test.go) |
| `RFC7515-S10_13-R01` | SHOULD | unit | TestAstralPlaneCharactersPreservedInComparison (rfc7515/rfc7515_test.go) |
