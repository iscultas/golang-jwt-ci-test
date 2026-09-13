# Requirement coverage: RFC8037

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 18 | 18 | 100% |
| MAY | 8 | 8 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC8037-S4-R02` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC8037-S2-R01` | MUST | unit | TestTheKeyTypeIsOKP (rfc8037/rfc8037_test.go) |
| `RFC8037-S2-R02` | MUST | unit | TestTheSubtypeIsRequired (rfc8037/rfc8037_test.go) |
| `RFC8037-S2-R03` | MUST | unit | TestThePublicKeyIsRequired (rfc8037/rfc8037_test.go) |
| `RFC8037-S2-R04` | MUST | unit | TestAPrivateKeyCarriesItsPrivateKeyInD (rfc8037/rfc8037_test.go) |
| `RFC8037-S2-R05` | MUST | unit | TestAPublicKeyCarriesNoD (rfc8037/rfc8037_test.go) |
| `RFC8037-S2-R06` | MUST | unit | TestTheThumbprintCoversCrvKtyAndX (rfc8037/rfc8037_test.go) |
| `RFC8037-S2-R07` | MAY | unit | TestANonCanonicalEncodingIsRefused (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_1-R01` | MUST | unit | TestAnEdDSASubtypeIsRefusedForKeyAgreement (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_1-R02` | MUST | unit | TestEdDSAIsTheAlgorithmIdentifier (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_1-R03` | MUST | unit | TestTheVariantComesFromTheSubtype (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_1_1-R01` | MUST | interop | TestThePublishedSignatureIsReproduced (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_1_2-R01` | MUST | interop | TestThePublishedSignatureVerifies (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_2-R01` | MUST | unit | TestAnECDHSubtypeNeverBecomesSigningMaterial (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_2-R02` | MUST | unit | TestTheWorkedExampleKeysParseToTheirPublishedOctets (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_2-R03` | MUST | unit | TestAnX25519TokenRoundTrips (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_2_1-R01` | MUST | unit | TestTheEphemeralPublicKeyIsTheBasePointProduct (rfc8037/rfc8037_test.go) |
| `RFC8037-S3_2_1-R02` | MUST | unit | TestTheAppendixA6AgreementDerivesFromThePublishedZ (rfc8037/rfc8037_test.go) |
| `RFC8037-S4-R01` | MUST | unit | TestSigningNeedsNoRandomness (rfc8037/rfc8037_test.go) |
| `RFC8037-S4-R02` | SHOULD | not-testable | -- |
| `RFC8037-S4-R03` | MUST | unit | TestAlgorithmsRefuseKeyMaterialOfAnotherSubtype (rfc8037/rfc8037_test.go) |
| `RFC8037-S4-R04` | MAY | unit | TestAKeyIdentifierInTheProtectedHeaderIsBound (rfc8037/rfc8037_test.go) |
| `RFC8037-S5-R01a` | MAY | unit | TestTheSupportedOptionalRegistrations (rfc8037/rfc8037_test.go) |
| `RFC8037-S5-R01b` | MAY | unit | TestTheSupportedOptionalRegistrations (rfc8037/rfc8037_test.go) |
| `RFC8037-S5-R01c` | MAY | unit | TestTheSupportedOptionalRegistrations (rfc8037/rfc8037_test.go) |
| `RFC8037-S5-R01d` | MAY | unit | TestTheUnsupportedOptionalRegistrationsAreRefusedByName (rfc8037/rfc8037_test.go) |
| `RFC8037-S5-R01e` | MAY | unit | TestTheWorkedExampleKeysParseToTheirPublishedOctets (rfc8037/rfc8037_test.go) |
| `RFC8037-S5-R01f` | MAY | unit | TestTheUnsupportedOptionalRegistrationsAreRefusedByName (rfc8037/rfc8037_test.go) |
