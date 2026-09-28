#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

shopt -s nullglob
casts=("$script_dir"/casts/*.cast)
shopt -u nullglob

if (( ${#casts[@]} == 0 )); then
  printf 'No demo casts found in %s/casts.\n' "$script_dir"
  exit 0
fi

for cast_path in "${casts[@]}"; do
  name=${cast_path##*/}
  "$script_dir/render.sh" "${name%.cast}"
done
