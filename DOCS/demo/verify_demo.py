#!/usr/bin/env python3
"""Sanity-check the states the demo recorder relies on (run with the dev servers up)."""
import asyncio

from playwright.async_api import async_playwright

import build_demo as b


async def main() -> None:
    ok = True
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        ctx = await browser.new_context(viewport={"width": b.W, "height": b.H})
        await ctx.add_init_script(
            f"try{{sessionStorage.setItem('skyforge.token','{b.TOKEN}');}}catch(e){{}}"
        )
        await ctx.add_init_script(b.CURSOR_JS)
        page = await ctx.new_page()

        def check(name: str, cond: bool, extra: str = "") -> None:
            nonlocal ok
            ok &= cond
            print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")

        # every route must render the authenticated shell, not the login form
        for scene in b.load_script()["scenes"]:
            route = scene["route"]
            if route.startswith("card:"):
                continue
            await page.goto(b.BASE_URL + route, wait_until="networkidle")
            await page.wait_for_timeout(1500)
            shell = await page.locator(".sidebar").count()
            login = await page.locator(".login").count()
            heading = (await page.locator("h1").first.inner_text()) if await page.locator("h1").count() else "—"
            empties = await page.locator("text=/Select a project/i").count()
            span = await page.evaluate("() => window.__sfMaxScroll(null)")
            moved = await page.evaluate("async () => await window.__sfScroll(null, 400, 300)")
            # /projects is a short page; its scene drives the Add-services dialog instead.
            needs_scroll = route != "/projects"
            good = shell == 1 and login == 0 and empties == 0 and (span > 100 or not needs_scroll)
            check(f"{route:<12} shell{' + scroll' if needs_scroll else ''}", good,
                  f'h1="{heading[:34]}" scrollspan={int(span)} moved={int(moved or 0)}')

        # caption overlay
        await page.evaluate("() => window.__sfCaption('Caption probe')")
        check("caption overlay renders", await page.locator("#sf-caption").count() == 1)

        # subtitles are opt-in (--subs): nothing should be drawn unless asked for
        check("no subtitle overlay by default", await page.locator("#sf-subs").count() == 0)

        probe = ("Security first. Every dependency is checked against the O S V database, "
                 "while guardrails enforce secrets, code, pipeline and infrastructure policy.")
        cues = b.split_cues(probe, 6.0)
        check("cue splitter produces multiple cues", len(cues) > 1, f"cues={len(cues)}")
        await page.evaluate("(c) => window.__sfSubs(c)", cues)
        await page.wait_for_timeout(400)
        first = await page.locator("#sf-subs").inner_text()
        await page.wait_for_timeout(cues[0]["d"] * 1000 + 400)
        second = await page.locator("#sf-subs").inner_text()
        check("subtitles work when --subs is passed", bool(first) and first != second,
              f'"{first[:30]}…" -> "{second[:30]}…"')

        # onboarding dialog
        await page.goto(b.BASE_URL + "/projects", wait_until="networkidle")
        await page.get_by_role("button", name="Add services").first.click()
        dlg = page.locator(".MuiDialog-container")
        await dlg.wait_for(state="visible", timeout=5000)
        await dlg.get_by_label("Service name").first.fill("Payments Gateway")
        await dlg.get_by_label("Repository link").first.fill("https://github.com/acme/payments-gateway")
        agents = await dlg.locator("text=/code health/i").count()
        check("add-services dialog + fields + agent list", agents > 0, f"agent-matches={agents}")
        await page.keyboard.press("Escape")

        # finding drawer with a real patch
        await page.goto(b.BASE_URL + "/findings", wait_until="networkidle")
        await page.wait_for_timeout(1500)
        row = page.locator("tr", has_text="aiohttp 3.8.1").first
        check("target finding row present", await row.count() > 0)
        await row.click()
        drawer = page.locator(".MuiDrawer-paper")
        await drawer.wait_for(state="visible", timeout=6000)
        await page.wait_for_timeout(1800)
        body = await drawer.inner_text()
        height = await drawer.evaluate("el => el.scrollHeight")
        check("drawer shows explanation", "Explanation" in body)
        check("drawer shows recommendation", "Recommendation" in body)
        check("drawer is scrollable", height > 1200, f"scrollHeight={height}")

        # v2 title cards
        for name, must in (("intro", ["Onboard every service", "Standardise every team",
                                      "six AI agents, human in the loop", "6 autonomous agents",
                                      "Draft pull requests"]),
                           ("outro", ["Better. Safer.", "Cheaper.", "Seconds", "to onboard",
                                      "$/month", "Cloud & Code Command"])):
            await page.goto(b.card_url(name, "v2"))
            await page.evaluate("async () => { await document.fonts.ready; }")
            await page.wait_for_timeout(2600)       # let entrance animations finish
            body = await page.locator("body").inner_text()
            low = body.lower()          # CSS text-transform uppercases some labels
            missing = [m for m in must if m.lower() not in low]
            check(f"{name}-v2 copy", not missing, f"missing={missing}")
            banned = [t for t in ("no single view of risk", "nobody owning the baseline")
                      if t in low]
            check(f"{name}-v2 old lines removed", not banned, f"found={banned}")
            font = await page.evaluate(
                "() => getComputedStyle(document.querySelector('h1')).fontFamily")
            loaded = await page.evaluate(
                '() => document.fonts.check(\'800 76px "Bricolage Grotesque"\')')
            check(f"{name}-v2 uses deck font", "Bricolage" in font and loaded,
                  f"font={font.split(',')[0]} loaded={loaded}")
            visible = await page.evaluate(
                "() => [...document.querySelectorAll('.a')]"
                ".every(e => getComputedStyle(e).opacity === '1')")
            check(f"{name}-v2 animations settle visible", visible)

        await browser.close()
    print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")


asyncio.run(main())



