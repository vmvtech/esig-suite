---
type: reference
title: Terminal Demo Recording and Rendering
created: 2026-09-28
tags:
  - demos
  - asciinema
  - release-assets
related:
  - '[[GAPS-AND-TODOS]]'
---

# Terminal demos

Terminal demos are recorded as text-based asciinema casts, then rendered to GIF and MP4. The committed `.cast` files in `demos/casts/` are the source of truth. Files in `demos/out/` are derived and ignored by Git; copy approved renders to their final package or site locations.

## Requirements

- `asciinema`
- `agg`
- `ffmpeg`

## Record and render

Run commands from the repository root:

```bash
bash demos/record.sh quickstart -- npm run quickstart --silent
bash demos/render.sh quickstart
```

The recorder fixes the terminal at 100 columns by 30 rows and limits idle time to one second. Rendering uses the Monokai theme at 16 px and produces:

- `demos/out/quickstart.gif`
- `demos/out/quickstart.mp4` at 1280×720

Render every committed cast with:

```bash
npm run demos
```

## Add a demo

1. Use only deterministic fixtures and `@example.com` identities. Never record credentials or personal data.
2. Record the exact public command with `demos/record.sh`.
3. Inspect the `.cast` file for sensitive or machine-specific output before committing it.
4. Render the cast and review the final GIF and MP4.
5. Commit the `.cast` source and copy the approved derived assets to the paths required by the corresponding feature documentation.
