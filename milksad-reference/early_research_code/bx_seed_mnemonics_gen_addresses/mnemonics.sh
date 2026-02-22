#!/bin/bash
set -euo pipefail

# Define default values
: "${INITIAL_VALUE:=0.000000000}"
: "${INCREMENT_STEP:=0.000000001}"
: "${END_VALUE:=4.294967296}"

psql -f ./sql/mnemonics.psql

# Loop until the current value reaches the end value
while (( $(echo "$INITIAL_VALUE <= $END_VALUE" | bc -l) )); do
  # Output the current value with desired formatting (e.g., 9 decimal places)
  seed=$(LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME_FMT=%s FAKETIME=$(printf "%.9f\n" $INITIAL_VALUE) bx seed -b 256 | bx mnemonic-new)
  printf "%.9f | %s\n" $INITIAL_VALUE "$seed"
  psql -c "insert into mnemonics (ts, mnemonic) values ('$INITIAL_VALUE', '$seed');"
  # Increment the current value
  INITIAL_VALUE=$(echo "$INITIAL_VALUE + $INCREMENT_STEP" | bc -l)
done

