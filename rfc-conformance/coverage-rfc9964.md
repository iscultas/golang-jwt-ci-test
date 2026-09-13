# Requirement coverage: RFC9964

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 11 | 11 | 100% |
| MAY | 4 | 4 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC9964-S7_3-R03` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC9964-S3-R01` | MUST | unit | TestAKPKeyRequiresAlgorithm (rfc9964/rfc9964_test.go) |
| `RFC9964-S3-R02` | MUST | unit | TestAKPKeyRequiresPublicKey (rfc9964/rfc9964_test.go) |
| `RFC9964-S3-R03` | MUST | unit | TestPrivateParameterIsAbsentFromPublicKeys (rfc9964/rfc9964_test.go) |
| `RFC9964-S3-R04` | MUST | unit | TestAKPParametersAreBase64url (rfc9964/rfc9964_test.go) |
| `RFC9964-S4-R01` | MUST | unit | TestPrivateParameterIsTheSeed (rfc9964/rfc9964_test.go) |
| `RFC9964-S5-R01` | MUST | unit | TestSignatureUsesTheEmptyContext (rfc9964/rfc9964_test.go) |
| `RFC9964-S5-R02` | MUST | unit | TestPublicKeyParameterWidths (rfc9964/rfc9964_test.go) |
| `RFC9964-S5-R03` | MUST | unit | TestSignatureEncoding (rfc9964/rfc9964_test.go) |
| `RFC9964-S6-R01` | MUST | unit | TestAKPThumbprint (rfc9964/rfc9964_test.go) |
| `RFC9964-S7_3-R01` | MUST | unit | TestEveryAlgorithmRelatedParameterIsValidated (rfc9964/rfc9964_test.go) |
| `RFC9964-S7_3-R02` | MUST | unit | TestSeedLengthCheck (rfc9964/rfc9964_test.go) |
| `RFC9964-S7_3-R03` | MUST | not-testable | -- |
| `RFC9964-S8_1_4-R01a` | MAY | unit | TestMLDSAAlgorithmIdentifiers (rfc9964/rfc9964_test.go), TestMLDSAIdentifierIsUsableEndToEnd (rfc9964/rfc9964_test.go) |
| `RFC9964-S8_1_4-R01b` | MAY | unit | TestMLDSAAlgorithmIdentifiers (rfc9964/rfc9964_test.go) |
| `RFC9964-S8_1_4-R01c` | MAY | unit | TestMLDSAAlgorithmIdentifiers (rfc9964/rfc9964_test.go) |
| `RFC9964-S8_1_5-R01` | MAY | unit | TestAKPKeyTypeIsSupported (rfc9964/rfc9964_test.go) |
