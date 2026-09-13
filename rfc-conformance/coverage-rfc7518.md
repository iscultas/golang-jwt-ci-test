# Requirement coverage: RFC7518

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 52 | 52 | 100% |
| SHOULD | 6 | 6 | 100% |
| MAY | 5 | 5 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC7518-S4_8-R01` (not-testable)
- `RFC7518-S6_3_2_7-R02` (not-testable)
- `RFC7518-S6_3_2_7-R04` (not-testable)
- `RFC7518-S8_4-R01` (not-testable)
- `RFC7518-S9-R01` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7518-S2-R01` | MUST | unit | TestBase64urlUIntUsesTheMinimumNumberOfOctets (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_1-R01` | MUST | unit | TestRequiredAlgorithmIsImplemented (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_1-R02` | SHOULD | unit | TestRecommendedAlgorithmsAreImplemented (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_1-R03` | MAY | unit | TestOptionalAlgorithmsAreOfferedOrReportedUnsupported (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_2-R01` | MUST | unit | TestHmacKeyIsAtLeastTheHashOutputSize (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_2-R02` | MUST | static | TestHmacComparisonIsConstantTime (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_3-R01` | MUST | unit | TestRsaKeyIsAtLeast2048Bits (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_4-R01` | MUST | property | TestEcdsaSignatureRetainsLeadingZeroOctets (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_4-R02` | MUST | unit | TestES256SignatureIsA64OctetSequence (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_4-R03` | MUST | unit | TestEcdsaAlgorithmIsBoundToItsCurve (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_4-R04` | MUST | unit | TestES384AndES512SignatureLengths (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_5-R01` | MUST | unit | TestRsaKeyIsAtLeast2048Bits (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_5-R02` | MUST | unit | TestRsassaPssUsesASaltOfTheHashLength (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_6-R01` | MAY | unit | TestUnsecuredJwsMayBeCreated (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_6-R02` | MUST | unit | TestUnsecuredJwsSignatureIsTheEmptyOctetSequence (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_6-R03` | MUST | unit | TestUnsecuredJwsRequiresAnEmptySignature (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_6-R04` | MUST | unit | TestUnsecuredJwsRequiresAnExplicitOptIn (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_6-R05` | MUST | unit | TestUnsecuredJwsIsRejectedByDefault (rfc7518/rfc7518_test.go) |
| `RFC7518-S3_6-R06` | MUST | unit | TestUnsecuredJwsAcceptanceIsPerCallRatherThanGlobal (rfc7518/rfc7518_test.go) |
| `RFC7518-S4_2-R01` | MUST | unit | TestAppendixA2Decrypts (rfc7516/vectors_test.go), TestRSA15RequiresA2048BitModulus (rfc7518/encryption_test.go), TestRSA15DecryptsAndDoesNotEncrypt (rfc7518/encryption_test.go) |
| `RFC7518-S4_3-R01` | MUST | unit | TestRSAOAEPRequiresA2048BitModulus (rfc7518/encryption_test.go) |
| `RFC7518-S4_6-R01` | MUST | unit | TestEphemeralKeyIsFreshForEveryAgreement (rfc7518/encryption_test.go) |
| `RFC7518-S4_6-R02` | MUST | unit | TestDirectKeyAgreementDerivesTheEncKeyLength (rfc7518/encryption_test.go) |
| `RFC7518-S4_6-R03` | MUST | unit | TestKeyAgreementWithKeyWrappingDerivesTheWrappingKeyLength (rfc7518/encryption_test.go), TestKeyAgreementModesDeriveDifferentKeys (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_1_1-R01` | MUST | unit | TestEphemeralPublicKeyCarriesOnlyPublicParameters (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_1_1-R02` | MUST | unit | TestEphemeralPublicKeyIsRequired (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_1_2-R01` | MAY | unit | TestAgreementPartyInfoIsOptional (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_1_2-R02` | MUST | unit | TestAgreementPartyInfoIsFedToTheKDF (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_1_3-R01` | MAY | unit | TestAgreementPartyInfoIsOptional (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_1_3-R02` | MUST | unit | TestAgreementPartyInfoIsFedToTheKDF (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_2-R01` | MUST | unit | TestAgreementPartyInfoMustBeDistinct (rfc7518/encryption_test.go) |
| `RFC7518-S4_6_2-R02` | MAY | unit | TestAgreementPartyInfoAcceptsAnyOctets (rfc7518/encryption_test.go) |
| `RFC7518-S4_7-R01` | MUST | unit | TestAESGCMKeyWrapUsesA96BitIV (rfc7518/encryption_test.go) |
| `RFC7518-S4_7-R02` | MUST | unit | TestAESGCMKeyWrapUsesA128BitTag (rfc7518/encryption_test.go) |
| `RFC7518-S4_7_1_1-R01` | MUST | unit | TestAESGCMKeyWrapRequiresIVAndTag (rfc7518/encryption_test.go) |
| `RFC7518-S4_7_1_2-R01` | MUST | unit | TestAESGCMKeyWrapRequiresIVAndTag (rfc7518/encryption_test.go) |
| `RFC7518-S4_8-R01` | MUST | not-testable | TestPBES2PasswordIsAnOctetSequence (rfc7518/encryption_test.go) |
| `RFC7518-S4_8-R02` | MUST | unit | TestPBES2BindsTheAlgorithmNameIntoTheSalt (rfc7518/encryption_test.go) |
| `RFC7518-S4_8-R03` | MUST | unit | TestPBES2IterationCountComesFromTheHeader (rfc7518/encryption_test.go) |
| `RFC7518-S4_8_1_1-R01` | MUST | unit | TestPBES2SaltInputIsRequiredAndProcessed (rfc7518/encryption_test.go) |
| `RFC7518-S4_8_1_1-R02` | MUST | unit | TestPBES2SaltInputFloor (rfc7518/encryption_test.go) |
| `RFC7518-S4_8_1_1-R03` | MUST | unit | TestPBES2SaltIsFreshForEveryEncryption (rfc7518/encryption_test.go) |
| `RFC7518-S4_8_1_2-R01` | MUST | unit | TestPBES2IterationCountIsRequired (rfc7518/encryption_test.go) |
| `RFC7518-S4_8_1_2-R02` | SHOULD | unit | TestPBES2IterationCountFloor (rfc7518/encryption_test.go) |
| `RFC7518-S5_2_2_1-R01` | MUST | unit | TestAESCBCHMACSHA2KeyLength (rfc7518/encryption_test.go) |
| `RFC7518-S5_3-R01` | MUST | unit | TestAESGCMContentEncryptionUsesA96BitIV (rfc7518/encryption_test.go) |
| `RFC7518-S5_3-R02` | MUST | unit | TestAESGCMContentEncryptionUsesA128BitTag (rfc7518/encryption_test.go) |
| `RFC7518-S6_2_1-R01` | MUST | unit | TestEllipticCurvePublicKeyRequiredMembers (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_2_1-R02` | MUST | unit | TestEllipticCurvePublicKeyRequiredMembers (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_2_1_2-R01` | MUST | unit | TestEllipticCurveMemberWidths (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_2_1_3-R01` | MUST | unit | TestEllipticCurveMemberWidths (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_2_2-R01` | MUST | unit | TestEllipticCurvePrivateKeyIncludesD (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_2_2_1-R01` | MUST | unit | TestEllipticCurveMemberWidths (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_1-R01` | MUST | unit | TestRsaPublicKeyRequiredMembers (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_1_2-R01` | MUST | unit | TestRsaExponentForTheUsualValue (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_2-R01` | MUST | unit | TestRsaPrivateKeyParameters (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_2-R02` | SHOULD | unit | TestRsaPrivateKeyParameters (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_2-R03` | MUST | unit | TestRsaPrivateKeyParameters (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_2_7-R01` | MUST | unit | TestTwoPrimeRsaKeyOmitsOth (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_2_7-R02` | MUST | not-testable | -- |
| `RFC7518-S6_3_2_7-R03` | MUST | unit | TestMultiPrimeRsaKeyIsRefused (rfc7518/rfc7518_test.go) |
| `RFC7518-S6_3_2_7-R04` | MUST | not-testable | -- |
| `RFC7518-S6_4-R01` | SHOULD | unit | TestSymmetricKeyCanDeclareItsAlgorithm (rfc7518/rfc7518_test.go) |
| `RFC7518-S8_4-R01` | MUST | not-testable | TestAESGCMInvocationLimitIsTheApplicationsToTrack (rfc7518/encryption_test.go) |
| `RFC7518-S8_4-R02` | MUST | unit | TestAESGCMIVIsNeverReused (rfc7518/encryption_test.go) |
| `RFC7518-S8_7-R01` | SHOULD | unit | TestKeyMaterialIsNotReusedAcrossMessages (rfc7518/encryption_test.go) |
| `RFC7518-S8_8-R01` | SHOULD | unit | TestPBES2PasswordLength (rfc7518/encryption_test.go) |
| `RFC7518-S9-R01` | SHOULD | not-testable | TestPasswordPreparationIsTheApplicationsToPerform (rfc7518/encryption_test.go) |
