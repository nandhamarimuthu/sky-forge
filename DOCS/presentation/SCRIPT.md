# SkyForge AI — Presenter Script

**Total time: ~8 minutes** (demo video 2:08 included) · Tone: calm, confident, no jargon.

---

## Slide 1 — Cover
> "Hi, we're SkyForge AI.
>
> One line: **onboard every service, standardise every team, and make each one better, safer and cheaper** — with six AI agents and a human always in the loop.
>
> Let me show you why that matters."

*(Beat. Click.)*

---

## Slide 2 — The problem · "Dozens of services. Every team with its own standards."
> "Here's what an enterprise estate actually looks like.
>
> Dozens — sometimes hundreds — of services. Every team doing things their own way. And nobody owns the baseline.
>
> So four things happen, quietly, all the time:
> - **Risk piles up.** Vulnerable dependencies age in repos nobody is watching.
> - **Tests lag behind.** Code grows faster than coverage.
> - **Cloud spend drifts.** Idle and oversized resources keep billing, every month.
> - **Debt compounds.** Complexity slows every future change.
>
> None of this is a tooling problem — scanners already tell you all of it. The problem is that **nothing closes the loop.** You get a list, not a fix."

---

## Slide 3 — The flow · "From repository to verified pull request"
> "SkyForge closes the loop. End to end, it's six steps.
>
> **Onboard** — paste a repo link. **Scan** — six agents run in parallel. **Guard** — every proposal is policy-checked. **Approve** — a human decides. **Verify** — the fix is proven in a Docker sandbox. **Deliver** — a draft pull request lands in your repo.
>
> Detection to merge-ready change. That's the whole product."

---

## Slide 4 — The agents · "Six specialists. One command centre."
> "The work is done by six specialists, not one generalist.
>
> Vulnerability remediation. Unit test and coverage. Functional automation. AWS cost optimisation. Code health. And security guardrails over all of it.
>
> Each one is narrow, each one has a strict tool allow-list, and each one produces **a patch — not a ticket.**"

---

## Slide 5 — Architecture · "How the platform fits together"
> "Briefly, under the hood: a FastAPI control plane, agents orchestrated with CrewAI, untrusted code executed only inside Docker, and a GitHub App for delivery using short-lived tokens.
>
> Nothing exotic. Boring, proven pieces — which is exactly what you want running against production repos."

---

## Slide 6 — Trust · "AI proposes. People decide."
> "This is the slide that matters most to a platform or security team.
>
> **No change without human approval.** Untrusted code runs **only** in a sandbox. The LLM runs **locally** — your code never leaves your environment. Every action is in the audit trail. And we **never** push to a default branch.
>
> SkyForge is not autonomous. It's an extremely well-prepared junior engineer who hands you a reviewed diff."

---

## Slide 7 — Product · "Every service, held to the same bar"
> "And because it's one control plane, you finally get one view of the estate.
>
> 47 critical and high vulnerabilities, prioritised. Unit coverage lifted from 14% to 78% with generated tests that actually pass. $4,850 a month of identified AWS savings, with the calculation behind every number. Code health from 61 to 86 after safe refactors.
>
> Same pipeline for every service: detect, explain, propose, validate, approve, verify, deliver. **Standardisation by default.**"

---

## Slide 8 — Live demo
> "Rather than talk about it — here it is, in the running product. Two minutes."

*(Play video. Say nothing over it.)*

> *(After)* "Everything you just saw was the real application: onboarding, agents, a sandbox-verified fix, and a draft PR."

---

## Slide 9 — Stack
> "Open, familiar technology throughout — React, FastAPI, CrewAI, Ollama running Gemma locally, Docker, OSV.dev for vulnerability data, Terraform for the cost model.
>
> No vendor lock-in, no data egress."

---

## Slide 10 — Roadmap · "From hackathon to platform"
> "Today: six agents across Python, JavaScript and Go.
>
> Next: CI-native — scheduled scans and pull-request checks in every pipeline. Then: read-only live AWS accounts. And the vision — fleet-wide org policy, SLAs and engineering insights."

---

## Slide 11 — Close
> "So, to land it:
>
> **Onboard in seconds. Hold every team to the same bar. Ship fixes that are already tested.**
>
> SkyForge AI. Thank you — happy to take questions."

---

## Cheat sheet — if asked

| Question | Answer |
|---|---|
| "Does it push code?" | Only draft PRs on a new branch. Never to default branches. |
| "Where does our code go?" | Nowhere. The LLM is Ollama/Gemma running locally. |
| "How do you know the fix works?" | We re-run the test suite in a Docker sandbox before the PR is opened. |
| "How is this different from Dependabot/Snyk?" | Those detect. SkyForge detects, fixes, **verifies**, and covers tests, cost and code health in one plane. |
| "Are the AWS numbers real?" | Simulated from your Terraform and CUR model today; live read-only accounts are next on the roadmap. |
| "What if the agent is wrong?" | Then a human rejects it. The cost of a wrong proposal is one review click. |

---

## Delivery tips
- Pause after the cover line and after "AI proposes, people decide." Both are the hooks.
- Don't read the cards on slides 2, 4 and 9 — name them, let the slide do the rest.
- Keep slides 5 and 9 to 20 seconds each; spend the time on 2, 6 and 7.

