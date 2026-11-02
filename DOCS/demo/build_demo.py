#!/usr/bin/env python3
"""
SkyForge AI — automated demo video builder.

Pipeline
  1. TTS      : edge-tts renders one narration clip per scene, giving exact durations.
  2. Record   : Playwright drives the live app, one video per scene, paced to its narration.
  3. Compose  : ffmpeg trims/pads each scene to its audio length, burns captions,
                concatenates, and muxes the voiceover -> skyforge-demo.mp4

Prerequisites (already handled by the repo setup):
  - API   on http://127.0.0.1:8000   (cd backend && ../.venv/bin/uvicorn app.main:app --port 8000)
  - Web   on http://localhost:5173   (cd frontend && npm run dev)
  - ffmpeg/ffprobe on PATH

Usage
  ../APP/.venv/bin/python build_demo.py              # full build
  ../APP/.venv/bin/python build_demo.py --skip-tts   # reuse narration audio
  ../APP/.venv/bin/python build_demo.py --compose-only
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
WORK = HERE / "build"
AUDIO_DIR = WORK / "audio"
VIDEO_DIR = WORK / "video"
SEG_DIR = WORK / "segments"
OUT = HERE.parent / "presentation" / "skyforge-demo.mp4"

BASE_URL = os.environ.get("SKYFORGE_WEB", "http://localhost:5173")
API_URL = os.environ.get("SKYFORGE_API", "http://127.0.0.1:8000")
TOKEN = os.environ.get("SKYFORGE_TOKEN", "change-me-admin-token")

W, H, FPS = 1920, 1080, 30
TAIL = 0.45           # breathing room appended to every scene's narration
GAP = 0.30            # silence inserted between scenes

# ---------------------------------------------------------------- utilities


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        sys.stderr.write(f"\n$ {' '.join(cmd[:9])} ...\n{p.stderr[-3000:]}\n")
        raise SystemExit(f"command failed: {cmd[0]}")
    return p


def probe_duration(path: Path) -> float:
    p = run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=nw=1:nk=1", str(path)])
    return float(p.stdout.strip())


def load_script() -> dict:
    return json.loads((HERE / "narration.json").read_text())


# ---------------------------------------------------------------- 1. voiceover


async def _tts(script: dict) -> None:
    import edge_tts

    AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    for scene in script["scenes"]:
        dest = AUDIO_DIR / f"{scene['id']}.mp3"
        print(f"  · tts {scene['id']:<9}", end="", flush=True)
        communicate = edge_tts.Communicate(
            scene["text"], script["voice"], rate=script["rate"], pitch=script["pitch"]
        )
        await communicate.save(str(dest))
        print(f" {probe_duration(dest):5.1f}s")


def synthesize(script: dict) -> list[float]:
    """Render narration and return per-scene durations (narration + TAIL)."""
    asyncio.run(_tts(script))
    return [probe_duration(AUDIO_DIR / f"{s['id']}.mp3") + TAIL for s in script["scenes"]]


# ---------------------------------------------------------------- subtitles

MAX_CUE = 88          # characters per subtitle card


def split_cues(text: str, speech: float) -> list[dict]:
    """Chunk narration into readable cues, timed proportionally to their length."""
    words, lines, cur = text.split(), [], ""
    for w in words:
        candidate = f"{cur} {w}".strip()
        # prefer breaking after sentence-final punctuation
        if len(candidate) > MAX_CUE and cur:
            lines.append(cur)
            cur = w
        else:
            cur = candidate
            if cur.endswith((".", "?", "!", ":")) and len(cur) > MAX_CUE * 0.3:
                lines.append(cur)
                cur = ""
    if cur:
        lines.append(cur)

    total = sum(len(l) for l in lines) or 1
    cues, clock = [], 0.0
    for i, line in enumerate(lines):
        share = speech * len(line) / total
        # last cue absorbs rounding so subtitles end exactly with the voice
        d = (speech - clock) if i == len(lines) - 1 else share
        cues.append({"t": round(clock, 3), "d": round(max(0.6, d), 3), "text": line})
        clock += share
    return cues


# ---------------------------------------------------------------- 2. recording

CURSOR_JS = """
(() => {
  // Runs at document-start, so never touch the DOM eagerly: build lazily on first use.
  const host = () => document.body || document.documentElement;

  const cursor = () => {
    let c = document.getElementById('sf-cursor');
    if (!c && host()) {
      c = document.createElement('div');
      c.id = 'sf-cursor';
      c.style.cssText = `position:fixed;left:50%;top:60%;width:26px;height:26px;border-radius:50%;
        background:rgba(145,87,255,.30);border:2.5px solid #9157FF;
        box-shadow:0 0 0 6px rgba(145,87,255,.12),0 6px 18px rgba(28,24,56,.28);
        z-index:2147483647;pointer-events:none;transform:translate(-50%,-50%);opacity:0;
        transition:left .45s cubic-bezier(.4,0,.2,1),top .45s cubic-bezier(.4,0,.2,1),
                   width .15s ease,height .15s ease,opacity .3s ease;`;
      host().appendChild(c);
    }
    return c;
  };

  window.__sfCursor = (x, y) => {
    const c = cursor();
    if (!c) return;
    c.style.opacity = '1'; c.style.left = x + 'px'; c.style.top = y + 'px';
  };

  window.__sfPulse = () => {
    const c = cursor();
    if (!c) return;
    c.style.width = '14px'; c.style.height = '14px';
    setTimeout(() => { c.style.width = '26px'; c.style.height = '26px'; }, 160);
  };

  // overlays use the pitch-deck typeface so the video matches the slides
  const fonts = () => {
    if (document.getElementById('sf-fonts') || !document.head) return;
    const l = document.createElement('link');
    l.id = 'sf-fonts';
    l.rel = 'stylesheet';
    l.href = 'https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,700&display=swap';
    document.head.appendChild(l);
  };
  const BODY = '"DM Sans",system-ui,-apple-system,sans-serif';

  window.__sfCaption = (text) => {
    if (!host()) return;
    fonts();
    let b = document.getElementById('sf-caption');
    if (!b) {
      b = document.createElement('div');
      b.id = 'sf-caption';
      b.style.cssText = `position:fixed;top:26px;left:50%;transform:translate(-50%,-14px);
        z-index:2147483646;pointer-events:none;display:flex;align-items:center;gap:12px;
        padding:12px 26px 12px 20px;border-radius:999px;
        background:rgba(255,255,255,.94);border:1px solid rgba(214,206,234,.8);
        box-shadow:0 1px 2px rgba(28,24,56,.04),0 14px 34px -16px rgba(91,63,180,.3);
        backdrop-filter:blur(8px);font-family:${BODY};color:#4A4668;
        font-size:20px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;white-space:nowrap;
        opacity:0;transition:opacity .5s ease,transform .5s ease;`;
      const bar = document.createElement('span');
      bar.style.cssText = 'width:30px;height:3px;border-radius:3px;background:linear-gradient(135deg,#FF5A5A,#C655AE 52%,#9157FF)';
      const t = document.createElement('span');
      t.id = 'sf-caption-t';
      b.appendChild(bar); b.appendChild(t);
      host().appendChild(b);
    }
    document.getElementById('sf-caption-t').textContent = text;
    requestAnimationFrame(() => { b.style.opacity = '1'; b.style.transform = 'translate(-50%,0)'; });
  };

  // Burned-in subtitles: cues are [{t, d, text}] in seconds, relative to this call.
  window.__sfSubs = (cues) => {
    if (!host()) return;
    fonts();
    let s = document.getElementById('sf-subs');
    if (!s) {
      s = document.createElement('div');
      s.id = 'sf-subs';
      s.style.cssText = `position:fixed;left:50%;bottom:52px;transform:translate(-50%,14px);
        z-index:2147483647;pointer-events:none;max-width:1280px;text-align:center;
        padding:20px 38px;border-radius:20px;
        background:rgba(255,255,255,.955);border:1px solid rgba(214,206,234,.7);
        box-shadow:0 1px 2px rgba(28,24,56,.04),0 18px 46px -18px rgba(91,63,180,.4);
        backdrop-filter:blur(10px);font-family:${BODY};color:#1C1838;
        font-size:31px;font-weight:500;line-height:1.35;letter-spacing:-.01em;
        opacity:0;transition:opacity .22s ease,transform .22s ease;`;
      host().appendChild(s);
    }
    (window.__sfSubTimers || []).forEach(clearTimeout);
    window.__sfSubTimers = [];
    const show = (text) => {
      s.textContent = text;
      s.style.opacity = '1'; s.style.transform = 'translate(-50%,0)';
    };
    const hide = () => { s.style.opacity = '0'; s.style.transform = 'translate(-50%,14px)'; };
    cues.forEach((c) => {
      window.__sfSubTimers.push(setTimeout(() => show(c.text), c.t * 1000));
      window.__sfSubTimers.push(setTimeout(hide, (c.t + c.d) * 1000));
    });
  };

  // The app scrolls an inner <main>, not the document — pick whichever actually scrolls.
  window.__sfScrollable = (sel) => {
    if (sel) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    const cands = [document.scrollingElement, document.documentElement, document.body,
                   ...document.querySelectorAll('main, .main, .MuiDrawer-paper')];
    let best = null, most = 0;
    for (const el of cands) {
      if (!el) continue;
      const over = el.scrollHeight - el.clientHeight;
      if (over > most) { most = over; best = el; }
    }
    return most > 40 ? best : null;
  };

  window.__sfMaxScroll = (sel) => {
    const el = window.__sfScrollable(sel);
    return el ? el.scrollHeight - el.clientHeight : 0;
  };

  window.__sfScroll = (sel, to, ms) => new Promise(res => {
    const node = window.__sfScrollable(sel);
    if (!node) return res(0);
    // the app sets `html { scroll-behavior: smooth }`, which fights a per-frame animation
    document.documentElement.style.scrollBehavior = 'auto';
    node.style.scrollBehavior = 'auto';
    const max = node.scrollHeight - node.clientHeight;
    const target = Math.max(0, Math.min(to, max));
    const from = node.scrollTop, delta = target - from, t0 = performance.now();
    const step = (t) => {
      const p = Math.min(1, (t - t0) / ms);
      node.scrollTop = from + delta * (p < .5 ? 2*p*p : 1 - Math.pow(-2*p+2, 2)/2);
      p < 1 ? requestAnimationFrame(step) : res(node.scrollTop);
    };
    requestAnimationFrame(step);
  });
})();
"""


class Stage:
    """Thin Playwright helper: visible cursor, eased scrolling, deadline pacing."""

    def __init__(self, page, deadline: float):
        self.page = page
        self.deadline = deadline

    @property
    def left(self) -> float:
        return self.deadline - time.monotonic()

    async def settle(self, s: float = 0.0) -> None:
        if s:
            await self.page.wait_for_timeout(s * 1000)

    async def point(self, locator, pause: float = 0.45) -> bool:
        try:
            box = await locator.bounding_box()
        except Exception:
            return False
        if not box:
            return False
        x = box["x"] + box["width"] / 2
        y = box["y"] + min(box["height"] / 2, 40)
        await self.page.evaluate("([x,y]) => window.__sfCursor && window.__sfCursor(x,y)", [x, y])
        await self.page.mouse.move(x, y, steps=18)
        await self.settle(pause)
        return True

    async def click(self, locator, pause: float = 0.7) -> bool:
        if not await self.point(locator):
            return False
        await self.page.evaluate("() => window.__sfPulse && window.__sfPulse()")
        try:
            await locator.click(timeout=4000)
        except Exception:
            return False
        await self.settle(pause)
        return True

    async def type(self, locator, text: str, delay: int = 55) -> bool:
        if not await self.click(locator, pause=0.15):
            return False
        try:
            await locator.type(text, delay=delay)
        except Exception:
            return False
        await self.settle(0.3)
        return True

    async def max_scroll(self, selector: str | None = None) -> float:
        try:
            return float(await self.page.evaluate("(s) => window.__sfMaxScroll(s)", selector))
        except Exception:
            return 0.0

    async def scroll_to(self, y: float, ms: int = 1400, selector: str | None = None) -> None:
        try:
            await self.page.evaluate(
                "async ([sel, to, ms]) => { await window.__sfScroll(sel, to, ms); }",
                [selector, y, ms],
            )
        except Exception as exc:
            print(f"  (scroll failed: {exc})", end="")
        await self.settle(ms / 1000 * 0.08)

    async def tour(self, stops: list[float], selector: str | None = None) -> None:
        """Eased scroll through `stops` (fractions of the scrollable height),
        spreading whatever time is left in the scene across them."""
        span = await self.max_scroll(selector)
        for i, frac in enumerate(stops):
            budget = max(0.0, self.left - 0.5) / max(1, len(stops) - i)
            ms = int(min(2200, max(700, budget * 0.55 * 1000)))
            await self.scroll_to(span * frac, ms, selector)
            await self.settle(max(0.0, min(2.0, budget - ms / 1000)))
            if self.left < 0.6:
                break

    async def hold(self) -> None:
        """Burn the rest of the scene budget with a gentle drift so it never freezes."""
        while self.left > 0.1:
            await self.page.wait_for_timeout(min(200, int(self.left * 1000)))


def card_url(name: str, variant: str | None) -> str:
    """`intro` + variant `v2` -> assets/intro-v2.html, falling back to assets/intro.html."""
    if variant:
        versioned = ASSETS / f"{name}-{variant}.html"
        if versioned.exists():
            return versioned.as_uri()
    return (ASSETS / f"{name}.html").as_uri()


async def scene_overview(stage: Stage) -> None:
    await stage.tour([0, 0.35, 0.7, 1.0, 0])


async def scene_onboard(stage: Stage) -> None:
    page = stage.page
    await stage.settle(0.6)
    await stage.click(page.get_by_role("button", name="Add services").first, pause=1.0)
    dialog = page.locator(".MuiDialog-container")
    try:
        await dialog.wait_for(state="visible", timeout=6000)
    except Exception:
        pass
    await stage.type(dialog.get_by_label("Service name").first, "Payments Gateway")
    await stage.type(dialog.get_by_label("Repository link").first,
                     "https://github.com/acme/payments-gateway", delay=28)
    await stage.settle(0.5)
    # show the agent baseline that is applied to every service
    await stage.point(dialog.locator("text=/code health/i").first, pause=0.9)
    await stage.scroll_to(10_000, 1100, ".MuiDialog-container")
    await stage.hold()
    try:
        await page.keyboard.press("Escape")
    except Exception:
        pass


async def scene_agents(stage: Stage) -> None:
    await stage.tour([0, 0.3, 0.65, 1.0])


async def scene_security(stage: Stage) -> None:
    await stage.tour([0, 0.32, 0.68, 1.0])


async def scene_fix(stage: Stage) -> None:
    page = stage.page
    await stage.settle(0.5)
    row = page.locator("tr", has_text="aiohttp 3.8.1").first
    if not await stage.click(row, pause=1.3):
        await stage.click(page.locator("tbody tr").first, pause=1.3)
    drawer = page.locator(".MuiDrawer-paper")
    try:
        await drawer.wait_for(state="visible", timeout=6000)
    except Exception:
        pass
    await stage.settle(0.8)
    await stage.tour([0, 0.3, 0.55, 0.8, 1.0], selector=".MuiDrawer-paper")
    await stage.hold()


async def scene_testing(stage: Stage) -> None:
    await stage.tour([0, 0.35, 0.7, 1.0])


async def scene_aws(stage: Stage) -> None:
    await stage.tour([0, 0.33, 0.68, 1.0])


async def scene_quality(stage: Stage) -> None:
    await stage.tour([0, 0.35, 0.7, 1.0])


SCENE_FN = {
    "overview": scene_overview,
    "onboard": scene_onboard,
    "agents": scene_agents,
    "security": scene_security,
    "fix": scene_fix,
    "testing": scene_testing,
    "aws": scene_aws,
    "quality": scene_quality,
}


async def _record(script: dict, durations: list[float], variant: str | None,
                  subs: bool = False) -> list[float]:
    from playwright.async_api import async_playwright

    if VIDEO_DIR.exists():
        shutil.rmtree(VIDEO_DIR)
    VIDEO_DIR.mkdir(parents=True)

    offsets: list[float] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--force-color-profile=srgb",
                                                 "--font-render-hinting=none",
                                                 "--hide-scrollbars"])
        for scene, dur in zip(script["scenes"], durations):
            sid = scene["id"]
            out_dir = VIDEO_DIR / sid
            ctx = await browser.new_context(
                viewport={"width": W, "height": H},
                record_video_dir=str(out_dir),
                record_video_size={"width": W, "height": H},
                base_url=BASE_URL,
            )
            # keep the app authenticated on every page of every scene
            await ctx.add_init_script(
                f"try{{sessionStorage.setItem('skyforge.token','{TOKEN}');"
                f"localStorage.setItem('skyforge.sidebar.collapsed','0');}}catch(e){{}}"
            )
            await ctx.add_init_script(CURSOR_JS)
            page = await ctx.new_page()
            t0 = time.monotonic()           # video recording starts about here
            print(f"  · record {sid:<9} {dur:5.1f}s", end="", flush=True)

            route = scene["route"]
            if route.startswith("card:"):
                await page.goto(card_url(route.split(":", 1)[1], variant))
                try:                        # let webfonts land before the animation starts
                    await page.evaluate("async () => { await document.fonts.ready; }")
                except Exception:
                    pass
                await page.wait_for_timeout(250)
            else:
                await page.goto(BASE_URL + route, wait_until="networkidle")
                try:
                    await page.wait_for_selector(".topbar, .login", timeout=12000)
                except Exception:
                    pass
                await page.wait_for_timeout(1200)   # let charts animate in
                caption = scene.get("caption")
                if caption:
                    try:
                        await page.evaluate(
                            "(t) => window.__sfCaption && window.__sfCaption(t)", caption
                        )
                    except Exception:
                        pass

            # optional burned-in subtitles, started exactly where this scene is trimmed to
            if subs:
                try:
                    await page.evaluate("(c) => window.__sfSubs && window.__sfSubs(c)",
                                        split_cues(scene["text"], dur - TAIL))
                except Exception:
                    pass

            offset = max(0.0, time.monotonic() - t0 - 0.10)
            offsets.append(offset)

            stage = Stage(page, time.monotonic() + dur)
            try:
                if route.startswith("card:"):
                    await stage.hold()
                else:
                    fn = SCENE_FN.get(sid)
                    if fn:
                        await fn(stage)
                    await stage.hold()
            except Exception as exc:                # never let one scene kill the build
                print(f"  (recovered: {type(exc).__name__}: {exc})", end="")
                await stage.hold()

            video = page.video
            await ctx.close()
            src = Path(await video.path())
            dest = VIDEO_DIR / f"{sid}.webm"
            shutil.move(src, dest)
            shutil.rmtree(out_dir, ignore_errors=True)
            print(f"  -> {probe_duration(dest):5.1f}s raw, trim@{offset:4.1f}s")
        await browser.close()
    return offsets


def record(script: dict, durations: list[float], variant: str | None,
           subs: bool = False) -> list[float]:
    return asyncio.run(_record(script, durations, variant, subs))


# ---------------------------------------------------------------- 3. compose


def compose(script: dict, durations: list[float], offsets: list[float],
            variant: str | None = None) -> Path:
    SEG_DIR.mkdir(parents=True, exist_ok=True)
    for f in SEG_DIR.glob("*"):
        f.unlink()

    segments: list[Path] = []
    for scene, dur, off in zip(script["scenes"], durations, offsets):
        sid = scene["id"]
        src = VIDEO_DIR / f"{sid}.webm"
        dst = SEG_DIR / f"{sid}.mp4"

        # Drop the page-load lead-in so the narration lines up with the visuals.
        # Captions/subtitles are rendered in-page (this ffmpeg has no drawtext/libass).
        vf = [f"trim=start={off:.3f}", "setpts=PTS-STARTPTS",
              f"fps={FPS}", f"scale={W}:{H}:force_original_aspect_ratio=decrease",
              f"pad={W}:{H}:(ow-iw)/2:(oh-ih)/2:color=#EFE9FB", "setsar=1",
              "tpad=stop_mode=clone:stop_duration=30"]
        run(["ffmpeg", "-y", "-i", str(src), "-vf", ",".join(vf), "-t", f"{dur:.3f}",
             "-an", "-c:v", "libx264", "-preset", "medium", "-crf", "20",
             "-pix_fmt", "yuv420p", "-g", str(FPS * 2), str(dst)])
        segments.append(dst)

    # video track
    listfile = WORK / "segments.txt"
    listfile.write_text("".join(f"file '{p}'\n" for p in segments))
    silent = WORK / "video.mp4"
    run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(listfile),
         "-c", "copy", str(silent)])

    # audio track: narration clips padded to their scene slot, separated by GAP
    inputs: list[str] = []
    filters: list[str] = []
    for i, (scene, dur) in enumerate(zip(script["scenes"], durations)):
        inputs += ["-i", str(AUDIO_DIR / f"{scene['id']}.mp3")]
        pad = dur + (GAP if i < len(durations) - 1 else 0)
        filters.append(
            f"[{i}:a]aresample=48000,aformat=sample_fmts=fltp:channel_layouts=stereo,"
            f"apad=whole_dur={pad:.3f}[a{i}]"
        )
    chain = "".join(f"[a{i}]" for i in range(len(durations)))
    filters.append(
        f"{chain}concat=n={len(durations)}:v=0:a=1,"
        "loudnorm=I=-16:TP=-1.5:LRA=11[out]"       # web-standard narration level
    )
    voice = WORK / "voice.m4a"
    run(["ffmpeg", "-y", *inputs, "-filter_complex", ";".join(filters),
         "-map", "[out]", "-c:a", "aac", "-b:a", "192k", str(voice)])

    suffix = f"-{variant}" if variant else ""
    out = OUT.with_name(f"skyforge-demo{suffix}.mp4")
    out.parent.mkdir(parents=True, exist_ok=True)
    run(["ffmpeg", "-y", "-i", str(silent), "-i", str(voice),
         "-map", "0:v:0", "-map", "1:a:0", "-c:v", "copy", "-c:a", "copy",
         "-movflags", "+faststart", "-shortest", str(out)])

    # refreshed poster frame for the deck
    run(["ffmpeg", "-y", "-ss", "4", "-i", str(out), "-frames:v", "1",
         "-q:v", "3", str(out.with_name(f"demo-poster{suffix}.jpg"))])
    return out


def write_srt(script: dict, durations: list[float]) -> None:
    def ts(t: float) -> str:
        h, r = divmod(t, 3600)
        m, s = divmod(r, 60)
        return f"{int(h):02d}:{int(m):02d}:{int(s):02d},{int(s % 1 * 1000):03d}"

    lines, clock = [], 0.0
    for i, (scene, dur) in enumerate(zip(script["scenes"], durations), 1):
        end = clock + dur - TAIL
        lines.append(f"{i}\n{ts(clock)} --> {ts(end)}\n{scene['text']}\n")
        clock += dur + GAP
    (HERE / "narration.srt").write_text("\n".join(lines))


# ---------------------------------------------------------------- entrypoint


def preflight() -> None:
    import urllib.error
    import urllib.request

    for name, url in (("web", BASE_URL), ("api", f"{API_URL}/docs")):
        try:
            urllib.request.urlopen(url, timeout=5)
        except urllib.error.HTTPError:
            pass
        except Exception as exc:
            raise SystemExit(f"{name} not reachable at {url} ({exc}). Start the dev servers first.")
    for tool in ("ffmpeg", "ffprobe"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} not found on PATH (brew install ffmpeg)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-tts", action="store_true", help="reuse build/audio/*.mp3")
    ap.add_argument("--compose-only", action="store_true", help="reuse audio and video clips")
    ap.add_argument("--variant", default=None,
                    help="e.g. v2 -> uses assets/<card>-v2.html, writes skyforge-demo-v2.mp4")
    ap.add_argument("--subs", action="store_true",
                    help="burn narration subtitles into the picture (off by default)")
    args = ap.parse_args()

    WORK.mkdir(exist_ok=True)
    script = load_script()
    if not args.compose_only:
        preflight()

    if args.skip_tts or args.compose_only:
        durations = [probe_duration(AUDIO_DIR / f"{s['id']}.mp3") + TAIL for s in script["scenes"]]
    else:
        print("[1/3] narration")
        durations = synthesize(script)

    offsets_file = WORK / "offsets.json"
    if args.compose_only:
        print("[2/3] screen recording — skipped")
        offsets = json.loads(offsets_file.read_text()) if offsets_file.exists() \
            else [0.0] * len(durations)
    else:
        print("[2/3] screen recording")
        offsets = record(script, durations, args.variant, args.subs)
        offsets_file.write_text(json.dumps(offsets))

    print("[3/3] composing")
    out = compose(script, durations, offsets, args.variant)
    write_srt(script, durations)

    total = sum(durations) + GAP * (len(durations) - 1)
    print(f"\n✓ {out}  ({total/60:.0f}m {total%60:02.0f}s)")


if __name__ == "__main__":
    main()










