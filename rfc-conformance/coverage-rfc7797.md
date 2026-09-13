# Requirement coverage: RFC7797

| Level | Covered | Total | % |
| --- | --- | --- | --- |
| MUST | 4 | 4 | 100% |
| SHOULD | 1 | 1 | 100% |
| MAY | 1 | 1 | 100% |

## Deliberately excluded

Requirements marked not-testable or manual. They still need a human to confirm the exclusion is honest, and an exclusion goes stale when the implementation changes underneath it.

- `RFC7797-S3-R03` (not-testable)
- `RFC7797-S5_1-R01` (not-testable)
- `RFC7797-S5_2-R01` (not-testable)
- `RFC7797-S5_2-R02` (not-testable)
- `RFC7797-S5_2-R03` (not-testable)
- `RFC7797-S5_3-R01` (not-testable)
- `RFC7797-S7-R01` (not-testable)

## Full matrix

| ID | Level | Testability | Tests |
| --- | --- | --- | --- |
| `RFC7797-S7-R03` | MUST | unit | TestFalseB64IsRefused (rfc7797/rfc7797_test.go) |
| `RFC7797-SAbstract-R01` | MUST | unit | TestFalseB64IsRefused (rfc7797/rfc7797_test.go) |
| `RFC7797-S3-R01` | MUST | unit | TestB64OutsideTheProtectedHeaderIsRefused (rfc7797/rfc7797_test.go) |
| `RFC7797-S6-R01` | MUST | unit | TestB64RequiresCritAndCritRequiresB64 (rfc7797/rfc7797_test.go) |
| `RFC7797-S3-R02` | MAY | unit | TestConformantUnencodedPayloadJWSIsRefused (rfc7797/rfc7797_test.go) |
| `RFC7797-S7-R02` | SHOULD | unit | TestB64IsOmittedRatherThanWrittenTrue (rfc7797/rfc7797_test.go) |
| `RFC7797-S3-R03` | MUST | not-testable | -- |
| `RFC7797-S5_1-R01` | MUST | not-testable | -- |
| `RFC7797-S5_2-R01` | MUST | not-testable | -- |
| `RFC7797-S5_2-R02` | MUST | not-testable | -- |
| `RFC7797-S5_2-R03` | MAY | not-testable | -- |
| `RFC7797-S5_3-R01` | MUST | not-testable | -- |
| `RFC7797-S7-R01` | SHOULD | not-testable | -- |
