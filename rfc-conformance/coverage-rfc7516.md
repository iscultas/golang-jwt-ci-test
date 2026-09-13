# Requirement coverage: RFC7516

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 42 | 42 | 100% |
| SHOULD | 1 | 1 | 100% |
| MAY | 4 | 4 | 100% |

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7516-S3-R01` | MAY | unit | TestJSONSerializationToleratesWhitespace (rfc7516/rfc7516_test.go) |
| `RFC7516-S3_2-R01` | MUST | unit | TestAMessageWithNoHeaderIsRefused (rfc7516/rfc7516_test.go) |
| `RFC7516-S3_2-R02` | MAY | unit | TestOptionalMembersAreAbsentWhenUnused (rfc7516/rfc7516_test.go) |
| `RFC7516-S4-R01` | MUST | unit | TestDuplicateHeaderParameterNameIsRejected (rfc7516/rfc7516_test.go) |
| `RFC7516-S4_1_2-R01` | MUST | unit | TestEncIsAlwaysAEADWithAFixedKeyLength (rfc7516/rfc7516_test.go), TestASignatureAlgorithmIsNotAnEnc (rfc7516/rfc7516_test.go) |
| `RFC7516-S4_1_2-R02` | MUST | unit | TestEncMustBePresent (rfc7516/rfc7516_test.go) |
| `RFC7516-S4_1_3-R01` | MAY | unit | TestAnUnknownCompressionAlgorithmIsRefused (rfc7516/rfc7516_test.go) |
| `RFC7516-S4_1_3-R02` | MUST | unit | TestZipIsReadFromTheProtectedHeaderOnly (rfc7516/rfc7516_test.go) |
| `RFC7516-S4_1_3-R03` | MAY | unit | TestCompressionIsAsymmetric (rfc7516/rfc7516_test.go) |
| `RFC7516-S4_1_3-R04` | MUST | unit | TestCompressionIsAsymmetric (rfc7516/rfc7516_test.go) |
| `RFC7516-S5_1-R01` | MUST | unit | TestTheCEKIsAlwaysTheLengthEncRequires (rfc7516/rfc7516_test.go) |
| `RFC7516-S5_2-R01` | MUST | unit | TestAtLeastOneRecipientMustValidate (rfc7516/rfc7516_test.go), TestAMessageWithNoServiceableRecipientIsInvalid (rfc7516/vectors_test.go) |
| `RFC7516-S5_2-R02` | MUST | unit | TestHeaderParameterNamesAreDisjointAcrossAllThreeHeaders (rfc7516/rfc7516_test.go), TestAnUnserviceableRecipientIsStillCheckedForDisjointness (rfc7516/vectors_test.go), TestAMalformedRecipientHeaderIsStillFatal (rfc7516/vectors_test.go) |
| `RFC7516-S5_2-R03` | MUST | unit | TestARecoveredCEKOfTheWrongLengthIsRejected (rfc7516/rfc7516_test.go) |
| `RFC7516-S5_2-R04` | MUST | unit | TestAtLeastOneRecipientMustValidate (rfc7516/rfc7516_test.go), TestNoPlaintextEscapesAFailedDecryption (rfc7516/rfc7516_test.go), TestARecipientWeCannotServeDoesNotInvalidateTheMessage (rfc7516/vectors_test.go), TestARecipientThatFailsLaterIsAlsoSkipped (rfc7516/vectors_test.go), TestTheOutcomeOfARecipientWeCouldNotOpenIsOpaque (rfc7516/vectors_test.go), TestTheOutcomeOfEachRecipientIsReported (rfc7516/vectors_test.go) |
| `RFC7516-S5_2-R05` | SHOULD | unit | TestUnacceptableAlgorithmsMakeAJWEInvalid (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_1-R01` | MUST | unit | TestCompactSerializationGrammar (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_1-R02` | MUST | unit | TestCompactSerializationRefusesWhatItCannotCarry (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R01a` | MUST | unit | TestJSONMembersCarryTheEncodedValues (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R01b` | MUST | unit | TestOptionalMembersAreAbsentRatherThanEmpty (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R02a` | MUST | unit | TestUnprotectedHeadersAreUnencodedJSONObjects (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R02b` | MUST | unit | TestOptionalMembersAreAbsentRatherThanEmpty (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R03a` | MUST | unit | TestJSONMembersCarryTheEncodedValues (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R03b` | MUST | unit | TestOptionalMembersAreAbsentRatherThanEmpty (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R04a` | MUST | unit | TestJSONMembersCarryTheEncodedValues (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R04b` | MUST | unit | TestOptionalMembersAreAbsentRatherThanEmpty (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R05` | MUST | unit | TestCiphertextIsAlwaysPresent (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R06a` | MUST | unit | TestJSONMembersCarryTheEncodedValues (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R06b` | MUST | unit | TestOptionalMembersAreAbsentRatherThanEmpty (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R07` | MUST | unit | TestRecipientsIsAnArrayOfObjects (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R08` | MUST | unit | TestRecipientsIsAnArrayOfObjects (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R09a` | MUST | unit | TestUnprotectedHeadersAreUnencodedJSONObjects (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R09b` | MUST | unit | TestOptionalMembersAreAbsentRatherThanEmpty (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R10a` | MUST | unit | TestJSONMembersCarryTheEncodedValues (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R10b` | MUST | unit | TestOptionalMembersAreAbsentRatherThanEmpty (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R11` | MUST | unit | TestARecipientNeedsBothAlgorithms (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R12` | MUST | unit | TestUnknownMembersAreIgnored (rfc7516/rfc7516_test.go), TestAnUnserviceableRecipientSurvivesARoundTrip (rfc7516/vectors_test.go) |
| `RFC7516-S7_2_1-R13` | MUST | unit | TestHeaderParameterNamesAreDisjointAcrossAllThreeHeaders (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_1-R14` | MUST | unit | TestOneCiphertextServesEveryRecipient (rfc7516/rfc7516_test.go), TestEitherRecipientOfAppendixA4Opens (rfc7516/vectors_test.go) |
| `RFC7516-S7_2_1-R15` | MUST | unit | TestEncOutsideTheProtectedHeaderIsRefused (rfc7516/rfc7516_test.go) |
| `RFC7516-S7_2_2-R01` | MUST | unit | TestFlattenedSyntaxHasNoRecipientsMember (rfc7516/rfc7516_test.go) |
| `RFC7516-S9-R01` | MUST | unit | TestSegmentCountDistinguishesJWSFromJWE (rfc7516/rfc7516_test.go) |
| `RFC7516-S9-R02` | MUST | unit | TestJSONMembersDistinguishJWSFromJWE (rfc7516/rfc7516_test.go) |
| `RFC7516-S9-R03a` | MUST | unit | TestTheAlgValueDistinguishesJWSFromJWE (rfc7516/rfc7516_test.go) |
| `RFC7516-S9-R03b` | MUST | unit | TestTheEncMemberDistinguishesJWSFromJWE (rfc7516/rfc7516_test.go) |
| `RFC7516-S11_4-R01` | MUST | unit | TestRSA1_5IsNoDecryptionOracle (rfc7516/rfc7516_test.go) |
| `RFC7516-S11_5-R01` | MUST | unit | TestFailuresAreIndistinguishable (rfc7516/rfc7516_test.go), TestRSA1_5SubstitutesARandomKey (rfc7516/rfc7516_test.go), TestEveryOctetOfTheTagIsCompared (rfc7516/rfc7516_test.go) |
