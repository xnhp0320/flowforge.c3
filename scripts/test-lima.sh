#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
instance=${LIMA_INSTANCE:-default}
exec limactl shell "$instance" -- sh "$repo/scripts/test-linux.sh" "$repo"
