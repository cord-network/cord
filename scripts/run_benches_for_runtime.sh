#!/bin/bash

# Runs all benchmarks for all pallets, for a given runtime, provided by $1
# Should be run on a reference machine to gain accurate benchmarks

runtime="$1"

echo "[+] Compiling benchmarks..."
#cargo build --profile production --locked --features=runtime-benchmarks

# Load all pallet names in an array.
PALLETS=($(
  ./target/production/cord benchmark pallet --list --chain="dev" |
    tail -n+2 |
    cut -d',' -f1 |
    sort |
    uniq
))

echo "[+] Benchmarking ${#PALLETS[@]} pallets for CORD runtime"

# Define the error file.
ERR_FILE="benchmarking_errors.txt"
# Delete the error file before each run.
rm -f $ERR_FILE

# Benchmark each pallet.
for PALLET in "${PALLETS[@]}"; do
  echo "[+] Benchmarking $PALLET for CORD runtime"

  output_file=""
  if [[ $PALLET == *"::"* ]]; then
    # translates e.g. "pallet_foo::bar" to "pallet_foo_bar"
    output_file="${PALLET//::/_}.rs"
  fi

  OUTPUT=$(
    ./target/production/cord benchmark pallet \
      --chain="dev" \
      --steps=50 \
      --repeat=20 \
      --pallet="$PALLET" \
      --extrinsic="*" \
      --execution=wasm \
      --wasm-execution=compiled \
      --header=./HEADER-GPL3 \
      --output="./runtime/src/weights/${output_file}" 2>&1
  )
  if [ $? -ne 0 ]; then
    echo "$OUTPUT" >>"$ERR_FILE"
    echo "[-] Failed to benchmark $PALLET. Error written to $ERR_FILE; continuing..."
  fi
done

# Update the block and extrinsic overhead weights.
echo "[+] Benchmarking block and extrinsic overheads..."
OUTPUT=$(
  ./target/production/cord benchmark overhead \
    --chain="dev" \
    --execution=wasm \
    --wasm-execution=compiled \
    --weight-path="runtime/constants/src/weights/" \
    --warmup=10 \
    --repeat=100 \
    --header=./HEADER-GPL3
)
if [ $? -ne 0 ]; then
  echo "$OUTPUT" >>"$ERR_FILE"
  echo "[-] Failed to benchmark the block and extrinsic overheads. Error written to $ERR_FILE; continuing..."
fi

# Check if the error file exists.
if [ -f "$ERR_FILE" ]; then
  echo "[-] Some benchmarks failed. See: $ERR_FILE"
else
  echo "[+] All benchmarks passed."
fi
