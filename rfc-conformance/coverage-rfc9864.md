# Requirement coverage: RFC9864

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 4 | 4 | 100% |
| SHOULD | 2 | 2 | 100% |
| MAY | 2 | 2 | 100% |

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC9864-S2_2-R01a` | MAY | unit | TestFullySpecifiedEdDSAAlgorithmIdentifiers (rfc9864/rfc9864_test.go), TestFullySpecifiedIdentifierIsUsableEndToEnd (rfc9864/rfc9864_test.go) |
| `RFC9864-S2_2-R01b` | MAY | unit | TestFullySpecifiedEdDSAAlgorithmIdentifiers (rfc9864/rfc9864_test.go) |
| `RFC9864-S3-R01a` | MUST | unit | TestJOSEKeyManagementIsFullySpecified (rfc9864/rfc9864_test.go), TestECDHESIsPolymorphicInItsCurve (rfc9864/rfc9864_test.go) |
| `RFC9864-S3-R01b` | MUST | unit | TestJOSEContentEncryptionIsFullySpecified (rfc9864/rfc9864_test.go) |
| `RFC9864-S4_1_2-R01` | SHOULD | unit | TestDeprecatedEdDSAIdentifierRemainsSupported (rfc9864/rfc9864_test.go) |
| `RFC9864-S5-R01` | MUST | unit | TestEd25519KeyRepresentationUnchangedFromEdDSA (rfc9864/rfc9864_test.go) |
| `RFC9864-S7-R01` | MUST | unit | TestKeySelectionRejectsAlgorithmMismatch (rfc9864/rfc9864_test.go) |
| `RFC9864-S7-R02` | SHOULD | unit | TestAlgorithmParameterRoundTrips (rfc9864/rfc9864_test.go) |
