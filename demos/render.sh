#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf 'Usage: %s NAME\n' "${0##*/}" >&2
}

if (( $# != 1 )); then
  usage
  exit 64
fi

name=$1
if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  printf 'Demo name must use only letters, numbers, dots, underscores, and hyphens.\n' >&2
  exit 64
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cast_path="$script_dir/casts/$name.cast"
gif_path="$script_dir/out/$name.gif"
mp4_path="$script_dir/out/$name.mp4"

if [[ ! -f "$cast_path" ]]; then
  printf 'Cast not found: %s\n' "$cast_path" >&2
  exit 66
fi

for tool in agg ffmpeg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s is required to render terminal demos.\n' "$tool" >&2
    exit 127
  fi
done

mkdir -p "$script_dir/out"

agg \
  --theme monokai \
  --font-size 16 \
  --cols 100 \
  --rows 30 \
  --idle-time-limit 1 \
  --last-frame-duration 3 \
  "$cast_path" \
  "$gif_path"

ffmpeg \
  -y \
  -i "$gif_path" \
  -movflags faststart \
  -pix_fmt yuv420p \
  -vf "scale=1280:720:force_original_aspect_ratio=decrease:force_divisible_by=2:flags=lanczos,pad=1280:720:(ow-iw)/2:(oh-ih)/2:color=#272822" \
  "$mp4_path"
