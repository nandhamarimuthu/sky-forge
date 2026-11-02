nothing overwrites draft 1.
# SkyForge AI — demo video

Automated, reproducible 2-minute product demo: Playwright drives the **live** app while an
edge-tts voiceover narrates, and ffmpeg composes the two into a synced MP4.

## Drafts

| File | Title cards |
|------|-------------|
| `../presentation/skyforge-demo-v2.mp4` | **draft 2 — embedded in `index.html`** — light cards matching the deck |
| `../presentation/skyforge-demo-v2.mp4` | **draft 2** — light cards matching `index.html` |

Both are kept. Each has a matching `demo-poster*.jpg`. Draft 2 is built with `--variant v2`,
nothing overwrites draft 1. Run `verify_deck.py` after changing which draft the deck embeds.
nothing overwrites draft 1.

Neither draft has on-screen subtitles. The capability still exists behind `--subs` if you ever
want them burned in, and `narration.srt` is always written for soft subs.

**Format** → 1920×1080, 30fps, H.264 + AAC, ~2m08s.

## Narrative

The script follows **problem → solution → working software**:

| # | Scene | Beat |
|---|-------|------|
| 1 | `intro` | **Problem** — dozens of services, every team its own standard, nobody owns the baseline |
| 2 | `overview` | **Solution** — one org-wide control plane, trended over time |
| 3 | `onboard` | Standardisation by default — paste a repo, the same baseline applies |
| 4 | `agents` | Six specialist agents, sandboxed, human-in-the-loop |
| 5 | `security` | OSV dependency checks + secrets/code/CI/IaC guardrails |
| 6 | `fix` | **Working** — the full loop: detect → explain → patch → verify → draft PR |
| 7 | `testing` | Generated tests actually executed; real pass rates and coverage movement |
| 8 | `aws` | Waste quantified, with the calculation behind each saving |
| 9 | `quality` | Maintainability as a number |
| 10 | `outro` | Onboard in seconds. Same bar for every team. Pre-tested fixes. |

Edit `narration.json` to change wording, voice, rate or pitch — scene durations are derived
from the rendered audio, so the visuals re-pace themselves automatically.

## Prerequisites

```bash
brew install ffmpeg
cd ../../APP && .venv/bin/pip install edge-tts playwright && .venv/bin/playwright install chromium
```

Both dev servers must be running (the demo records the real UI against real data):

```bash
cd APP/backend  && ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
cd APP/frontend && npm run dev
```

## Build

```bash
cd DOCS/demo
../../APP/.venv/bin/python verify_demo.py                       # assert every scene's UI state first
../../APP/.venv/bin/python build_demo.py --variant v2           # draft 2 (light cards, no subtitles)
../../APP/.venv/bin/python build_demo.py                        # draft 1 (original cards)
../../APP/.venv/bin/python build_demo.py --variant v2 --subs    # same, with burned-in subtitles
../../APP/.venv/bin/python build_demo.py --skip-tts --variant v2    # reuse narration, re-record
../../APP/.venv/bin/python build_demo.py --compose-only --variant v2 # just re-cut existing clips
```

`verify_demo.py` is the guardrail: it checks each route renders the authenticated shell (not the
login form), that pages are scrollable, the Add-services dialog accepts input, the finding drawer
opens with an explanation/recommendation/patch, that no subtitle overlay is drawn unless asked
for, and that both v2 cards carry the right copy in the deck typeface. Run it whenever the UI
changes.

## How it stays in sync

1. **TTS first.** Each scene's narration is rendered to `build/audio/<id>.mp3`; its measured
   duration (+`TAIL`) becomes that scene's budget.
2. **Recording is deadline-driven.** `Stage` tracks the remaining budget and spreads eased
   scrolling across it, so visuals never finish early or run long.
3. **The lead-in is trimmed away.** Each scene records how long page-load took and stores that
   offset, so composition cuts straight to the ready UI instead of a loading screen.
4. **Composition is exact.** Every clip is `tpad`-extended then hard-trimmed to its budget, so
   audio and video can't drift; narration is normalised to −16 LUFS.

The scene caption (the small top-centre topic pill) is drawn as a themed in-page overlay in DM
Sans with the deck's colours, rather than ffmpeg `drawtext` — this Homebrew ffmpeg ships without
libfreetype/libass, and rendering in-page keeps the styling consistent with the slides.

Subtitles use the same mechanism and are **off by default**. With `--subs`, the narration is split
into ≤88-character cues timed proportionally to their length, so the last cue lands exactly with
the voice. `narration.srt` is emitted either way if you prefer soft subs in the player.

Config via env vars: `SKYFORGE_WEB`, `SKYFORGE_API`, `SKYFORGE_TOKEN`.

## Files

```
narration.json   scene script — voice, rate, pitch, captions, routes
build_demo.py    the pipeline (TTS → Playwright → ffmpeg)
verify_demo.py   pre-flight UI assertions
narration.srt    generated subtitles for the final cut
assets/          intro/outro title cards + logo
build/           intermediates (audio, per-scene video, segments) — regenerable
```

