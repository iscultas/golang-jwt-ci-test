# Benchmark results

A comparison of `github.com/iscultas/jwt-go` with `github.com/golang-jwt/jwt/v5`
v5.3.1 and `github.com/lestrrat-go/jwx/v3` v3.2.0.

| | |
| --- | --- |
| Machine | Apple M4 Max, darwin/arm64, on mains power |
| Go | 1.27.0 |
| Date | 2026-09-08 |
| Samples | 10 for each benchmark |
| Statistics | `benchstat`, median with a 95% confidence interval |

Mains power is in that table because it changes the result. The same suite on the
same machine on battery gave times about 60% longer, and the same allocation
counts to the unit. The three libraries slow down together, thus the percentages
below hold in the two conditions, but no absolute time from a machine on battery
is a time for the hardware.

A percentage compares with jwt-go. A `~` says that `benchstat` found no
difference larger than the noise (p > 0.05). A `—` says that the library does not
do that operation at all: golang-jwt implements JWS and JWT only, thus it has no
JWE and no JWK.

Read [README.md](README.md) before these numbers. It records what each benchmark
measures, the rules that make the arms comparable, and three places where two
columns are not the same work.

Bytes allocated are not in these tables. Against jwx they follow the allocation
counts in every row, thus a column of them would say what the counts say already.
Against golang-jwt they do not, and the difference goes both ways: jwt-go signs
with fewer blocks and 5% to 25% fewer bytes, and it verifies with fewer blocks and
1.6% to 3.0% more bytes. `BenchmarkParse` is the widest of them, where jwt-go
allocates 17 blocks against 37 and 1.743 KiB against 1.331 KiB. A block of jwt-go
is thus smaller on average than a block of golang-jwt, and the two counts do not
rank the two libraries the same way. The samples hold the bytes for every row.

## Signing

### Time

| Algorithm | jwt-go (base) | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 1.951 µs | 1.992 µs (+2.08%) | 3.084 µs (+58.05%) |
| `RS256` | 718.7 µs | 712.7 µs (-0.84%) | 818.3 µs (+13.86%) |
| `PS256` | 715.7 µs | 715.9 µs (~) | 810.7 µs (+13.29%) |
| `ES256` | 15.55 µs | 17.75 µs (+14.20%) | 20.00 µs (+28.63%) |
| `EdDSA` | 14.22 µs | 14.31 µs (+0.64%) | 26.31 µs (+85.05%) |

### Allocations

| Algorithm | jwt-go (base) | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 29 | 44 (+51.72%) | 75 (+158.62%) |
| `RS256` | 27 | 42 (+55.56%) | 127 (+370.37%) |
| `PS256` | 32 | 47 (+46.88%) | 133 (+315.62%) |
| `ES256` | 85 | 103 (+21.18%) | 156 (+83.53%) |
| `EdDSA` | 24 | 41 (+70.83%) | 78 (+225.00%) |

## Verification

### Time

| Algorithm | jwt-go (base) | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 2.167 µs | 2.706 µs (+24.87%) | 6.635 µs (+206.16%) |
| `RS256` | 23.41 µs | 23.90 µs (+2.09%) | 28.21 µs (+20.50%) |
| `PS256` | 23.81 µs | 24.45 µs (+2.69%) | 28.64 µs (+20.29%) |
| `ES256` | 37.58 µs | 37.60 µs (~) | 42.44 µs (+12.93%) |
| `EdDSA` | 28.39 µs | 28.68 µs (+1.05%) | 33.20 µs (+16.96%) |

### Allocations

| Algorithm | jwt-go (base) | golang-jwt | jwx |
| --- | --- | --- | --- |
| `HS256` | 26 | 46 (+76.92%) | 144 (+453.85%) |
| `RS256` | 31 | 51 (+64.52%) | 165 (+432.26%) |
| `PS256` | 35 | 55 (+57.14%) | 169 (+382.86%) |
| `ES256` | 42 | 62 (+47.62%) | 186 (+342.86%) |
| `EdDSA` | 20 | 40 (+100.00%) | 154 (+670.00%) |

## Parsing, with no check of the signature

### Time

| Operation | jwt-go (base) | golang-jwt | jwx |
| --- | --- | --- | --- |
| `compact JWS` | 1.538 µs | 2.233 µs (+45.22%) | 5.753 µs (+274.06%) |

### Allocations

| Operation | jwt-go (base) | golang-jwt | jwx |
| --- | --- | --- | --- |
| `compact JWS` | 17 | 37 (+117.65%) | 125 (+635.29%) |

## Encryption

### Time

| Algorithm | jwt-go (base) | jwx |
| --- | --- | --- |
| `dir` | 2.136 µs | 5.589 µs (+161.66%) |
| `A256KW` | 2.835 µs | 6.296 µs (+122.12%) |
| `ECDH-ES+A256KW` | 35.83 µs | 41.47 µs (+15.76%) |
| `RSA-OAEP-256` | 23.93 µs | 27.76 µs (+15.96%) |

### Allocations

| Algorithm | jwt-go (base) | jwx |
| --- | --- | --- |
| `dir` | 27 | 138 (+411.11%) |
| `A256KW` | 33 | 147 (+345.45%) |
| `ECDH-ES+A256KW` | 74 | 233 (+214.86%) |
| `RSA-OAEP-256` | 44 | 155 (+252.27%) |

## Decryption

### Time

| Algorithm | jwt-go (base) | jwx |
| --- | --- | --- |
| `dir` | 2.575 µs | 8.768 µs (+240.55%) |
| `A256KW` | 3.076 µs | 9.600 µs (+212.09%) |
| `ECDH-ES+A256KW` | 37.43 µs | 48.40 µs (+29.32%) |
| `RSA-OAEP-256` | 699.5 µs | 708.8 µs (+1.34%) |

### Allocations

| Algorithm | jwt-go (base) | jwx |
| --- | --- | --- |
| `dir` | 26 | 207 (+696.15%) |
| `A256KW` | 30 | 219 (+630.00%) |
| `ECDH-ES+A256KW` | 67 | 327 (+388.06%) |
| `RSA-OAEP-256` | 34 | 218 (+541.18%) |

## JWK

### Time

| Operation | jwt-go (base) | jwx |
| --- | --- | --- |
| parse one JWK | 926.9 ns | 2.891 µs (+211.90%) |
| write one JWK | 925.8 ns | 1.210 µs (+30.64%) |
| RFC 7638 thumbprint | 489.9 ns | 1.362 µs (+178.04%) |
| select from a set of four | 98.82 ns | 19.94 ns (-79.82%) |

### Allocations

| Operation | jwt-go (base) | jwx |
| --- | --- | --- |
| parse one JWK | 12 | 61 (+408.33%) |
| write one JWK | 8 | 36 (+350.00%) |
| RFC 7638 thumbprint | 8 | 23 (+187.50%) |
| select from a set of four | 0 | 0 (~) |
