#!/bin/bash -eu

# build fuzzer

pushd fuzzing
./build.sh
mv ./cmake-build-fuzz/fuzz_message $OUT/app-solana-fuzz-message
popd

