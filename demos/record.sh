#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf 'Usage: %s NAME -- CMD...\n' "${0##*/}" >&2
}

if (( $# < 3 )) || [[ "$2" != "--" ]]; then
  usage
  exit 64
fi

name=$1
shift 2

if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  printf 'Demo name must use only letters, numbers, dots, underscores, and hyphens.\n' >&2
  exit 64
fi

if ! command -v asciinema >/dev/null 2>&1; then
  printf 'asciinema is required to record terminal demos.\n' >&2
  exit 127
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$script_dir/casts"

printf -v command '%q ' "$@"
command=${command% }

asciinema rec \
  --overwrite \
  --headless \
  --window-size 100x30 \
  -i 1 \
  -c "$command" \
  "$script_dir/casts/$name.cast"
