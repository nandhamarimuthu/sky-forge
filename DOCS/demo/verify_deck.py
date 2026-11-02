#!/usr/bin/env python3
"""Check the deck's demo slide loads draft 2 and can actually play it."""
import asyncio
from pathlib import Path

from playwright.async_api import async_playwright

DECK = Path(__file__).resolve().parent.parent / "presentation" / "index.html"


async def main() -> None:
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page(viewport={"width": 1600, "height": 900})
        bad: list[str] = []
        page.on("requestfailed", lambda r: bad.append(f"{r.url.split('/')[-1]} {r.failure}"))
        page.on("response", lambda r: bad.append(f"{r.url.split('/')[-1]} HTTP {r.status}")
                if r.status >= 400 else None)

        await page.goto(DECK.as_uri())
        await page.wait_for_timeout(1500)

        v = page.locator("#demoVideo")
        src = await v.get_attribute("src")
        poster = await v.get_attribute("poster")
        check("deck points at draft 2 video", "skyforge-demo-v2.mp4" in src, src)
        check("deck points at draft 2 poster", "demo-poster-v2.jpg" in poster, poster)

        # force metadata + a real play so a broken/missing file surfaces
        await page.evaluate("async () => { const v = document.getElementById('demoVideo');"
                            " v.muted = true; v.load(); await v.play().catch(() => {}); }")
        await page.wait_for_timeout(2500)
        info = await page.evaluate(
            "() => { const v = document.getElementById('demoVideo');"
            " return {d: v.duration, w: v.videoWidth, h: v.videoHeight,"
            "         t: v.currentTime, err: v.error && v.error.code, rs: v.readyState}; }")
        check("video metadata loads", info["w"] == 1920 and info["h"] == 1080,
              f"{info['w']}x{info['h']} readyState={info['rs']} err={info['err']}")
        check("duration is the 2:08 cut", 125 < (info["d"] or 0) < 130, f"{info['d']:.1f}s")
        check("video actually plays", info["t"] > 0.2, f"currentTime={info['t']:.2f}s")
        # slides are visibility:hidden until active, so read text_content not inner_text
        label = await page.locator("[data-video] .side").text_content()
        check("label matches runtime", "2:08" in label, label.strip()[-46:])
        # our explicit v.load() cancels the initial range request; that abort is expected
        real = [b for b in bad if "ERR_ABORTED" not in b]
        check("no failed requests", not real, str(real[:4]))

        await browser.close()
    print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")


asyncio.run(main())


