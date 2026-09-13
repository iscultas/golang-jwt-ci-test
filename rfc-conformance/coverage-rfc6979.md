# Requirement coverage: RFC6979

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 5 | 5 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC6979-S4-R01` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC6979-SA_2-R01` | MUST | interop | TestPublishedVectorsAreReproduced (rfc6979/rfc6979_test.go) |
| `RFC6979-SA_2-R02` | MUST | interop | TestPublishedSignaturesVerify (rfc6979/rfc6979_test.go) |
| `RFC6979-SA_2-R03` | MUST | interop | TestPublishedKeysDeriveTheirPublishedPublicKey (rfc6979/rfc6979_test.go) |
| `RFC6979-S3_2-R01` | MUST | unit | TestSigningIsDeterministic (rfc6979/rfc6979_test.go) |
| `RFC6979-S3_2-R02` | MUST | unit | TestNonceVariesWithTheMessage (rfc6979/rfc6979_test.go) |
| `RFC6979-S4-R01` | SHOULD | not-testable | -- |
