#!/bin/sh

set -eu

if [ -z "${DC:-}" ]; then
  echo "Missing env variable: \$DC"
  echo "\$DC must be set to the name or full path of D compiler (e.g. 'dmd')"
  return 1
fi

if [ -z "${CODECOV_DIR:-}" ]; then
  echo "Missing env variable: \$CODECOV_DIR"
  echo "Set \$CODECOV_DIR to the path where coverage files should be saved"
  return 1
fi

mkdir -p "$CODECOV_DIR"
dub build --compiler="$DC"
dub test --compiler="$DC" --build=unittest-cov -- --DRT-covopt="dstpath:$CODECOV_DIR"
