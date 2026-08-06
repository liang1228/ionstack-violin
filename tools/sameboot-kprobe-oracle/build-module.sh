#!/bin/sh
set -eu

# Use the exact configured/build output tree for the rooted device kernel.
# Example: KDIR=/path/to/out/violin-gki make -C "$KDIR" M="$PWD" modules
: "${KDIR:?set KDIR to the exact Violin kernel build/output directory}"
exec make -C "$KDIR" M="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)" modules
