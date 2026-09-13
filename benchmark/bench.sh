#!/bin/sh
# Runs the comparison and writes the result to results.txt.
#
# The count is 10 because one run of a benchmark is not a measurement. benchstat
# needs repetitions to give a confidence interval, and it reports "~" when the
# difference between two libraries is not larger than the noise.
#
# Give a pattern to limit the run, for example:
#
#	./bench.sh BenchmarkVerify
#	./bench.sh 'BenchmarkSign/lib=jwx'

set -eu

cd "$(dirname "$0")"

pattern="${1:-.}"
count="${BENCH_COUNT:-10}"
output="${BENCH_OUTPUT:-results.txt}"

# -run='^$' keeps the correctness tests out of the timed run. Run them first, on
# their own, because an arm that fails reports a time for work it did not do.
go test -run=. -count=1 ./...

go test -run='^$' -bench="$pattern" -benchmem -count="$count" ./... | tee "$output"

cat <<MESSAGE

Wrote $output. To compare the libraries side by side:

	go run golang.org/x/perf/cmd/benchstat@latest -col /lib -row '.name,/alg' $output

benchstat is not a dependency of this module. It reads the "key=value" parts of
each benchmark name, and a leading slash names such a part, thus -col /lib gives
one column for each library and jwtgo becomes the column the others compare to.
MESSAGE
