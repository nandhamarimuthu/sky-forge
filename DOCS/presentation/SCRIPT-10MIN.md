# SkyForge AI — 10 Minute Presentation Script

**Total: 10:00** · 12 slides · Pace ~140 words/min
Rule: each slide introduces something *new*. Never re-explain a previous slide.

| # | Slide | Time | Running |
|---|-------|------|---------|
| 1 | Cover | 0:30 | 0:30 |
| 2 | The challenge | 1:00 | 1:30 |
| 3 | Why SkyForge AI | 0:50 | 2:20 |
| 4 | The flow | 0:40 | 3:00 |
| 5 | Six agents | 1:00 | 4:00 |
| 6 | Architecture | 0:50 | 4:50 |
| 7 | Trust by design | 0:40 | 5:30 |
| 8 | Delivery capacity | 0:50 | 6:20 |
| 9 | Live demo (video 2:08) | 2:20 | 8:40 |
| 10 | Under the hood | 0:40 | 9:20 |
| 11 | Roadmap | 0:25 | 9:45 |
| 12 | Close | 0:15 | 10:00 |

---

## 1 · Cover — *SkyForge AI, Cloud & Code Command* (0:30)

> Good morning. This is **SkyForge AI** — a Cloud and Code Command centre.
>
> In the next ten minutes I'll show you one workflow that takes a repository, finds what's wrong with it across security, testing, cost and quality, fixes it, proves the fix works in a sandbox, and hands you a pull request to review.
>
> Let me start with the problem we actually have.

*Cue: advance on "the problem we actually have."*

---

## 2 · The challenge — *Dozens of services, every team with its own standards* (1:00)

> We don't run one application. We run dozens of services, built by different teams, at different times, to different standards.
>
> Four things happen quietly as a result.
>
> **Risk piles up** — vulnerable dependencies sit in services nobody owns this quarter.
>
> **Tests lag behind** — coverage is a number on a dashboard, not a safety net, and nobody has the days to go back and write them.
>
> **Cloud spend drifts** — instances sized for a launch two years ago are still running, and the saving is always smaller than the effort to chase it.
>
> **And debt compounds** — complexity and duplication grow faster than anyone reviews them.
>
> None of this is hard engineering. It's *volume*. It's work that is well understood, repetitive, and never urgent enough to beat a roadmap item.

---

## 3 · Why SkyForge AI — *Six tools, six tickets. Or one workflow.* (0:50)

> And here's what makes it worse: the fix for each of those problems lives in a different place.
>
> Dependencies in a bot. Coverage in CI logs. Functional tests in a QA suite. Cost in the cloud console. Quality in a dashboard. Policy in a scanner.
>
> Six platforms, six tickets, six context switches — and no single view of whether a service is actually healthy.
>
> SkyForge collapses that into **one workflow**: one scan, one review, one draft pull request. Same six concerns — one place to act on them.

*Point at the "Today" column, then sweep right to the "With" column. Don't read the numbers — they animate.*

---

## 4 · The flow — *From repository to verified pull request* (0:40)

> The workflow is six steps, and it's the same every time.
>
> **Onboard** — paste a repository link. **Scan** — six agents run in parallel, not in a queue. **Guard** — every proposed change is validated against policy before a human ever sees it. **Approve** — an engineer decides, finding by finding. **Verify** — the approved fix is applied on an isolated branch and tested inside a Docker sandbox. **Deliver** — a draft pull request, with evidence attached.
>
> Nothing reaches your repository that hasn't been approved *and* proven.

---

## 5 · Six agents — *Six specialists, one command centre* (1:00)

> Those agents are specialists, each with a strictly limited toolset.
>
> **Vulnerability Remediation** queries OSV.dev and proposes the *minimal compatible* upgrade — not a blanket bump.
>
> **Unit Test & Coverage** measures real coverage and writes tests that have to pass before they're offered to you.
>
> **Functional Automation** maps the API journeys and fills the gaps between them.
>
> **AWS Cost Optimiser** reads your Terraform and returns rightsizing, Graviton and storage savings — as a patch, not a recommendation.
>
> **Code Health** finds the complexity, maintainability and duplication hotspots worth the effort.
>
> And **Security Guardrails** covers secrets, code, CI and infrastructure policy — and validates every fix the other five produce.
>
> That last one matters: the agents check each other.

---

## 6 · Architecture — *How the platform fits together* (0:50)

> Architecturally it's deliberately simple.
>
> We **ingest** the repository — clone, detect languages and frameworks. The **orchestrator** dispatches all six agents in parallel. They run on **CrewAI** with per-agent tool allow-lists — an agent can only call the tools it's been granted.
>
> Findings and fixes come back through **guardrails**, then to **human approval**, then **apply and verify** on an isolated branch, and finally **publish** via a GitHub App as a draft pull request.
>
> Underneath: a data store for findings and audit, a Terraform-and-pricing cost model, the Docker sandbox, OSV.dev for vulnerability intelligence — and a **local LLM**, Gemma 3 on Ollama.

*Hold one beat on "local LLM" — it sets up the next slide.*

---

## 7 · Trust by design — *AI proposes. People decide.* (0:40)

> Which brings me to the part that usually decides whether a tool like this is allowed anywhere near production.
>
> **No change without human approval.** The AI proposes; a person decides.
>
> **Untrusted code only ever runs in a sandbox** — isolated, no network to anything that matters.
>
> **Your code never leaves the environment.** The model is local. Nothing is sent to a third-party API.
>
> **Every action is in the audit trail**, and the platform **never pushes to a default branch** — only draft pull requests.
>
> Those aren't settings. They're constraints in the architecture.

---

## 8 · Delivery capacity — *20 effort days of tech debt. Now 10.* (0:50)

> So what's it worth?
>
> On our own measured baselines, tech debt absorbs around **twenty effort days** of delivery capacity. With SkyForge that's about **ten** — and that number *includes* the engineer reviewing and approving every generated pull request.
>
> Vulnerabilities: five days down to two. Unit tests: three to one. Functional tests: four to two. Code health: five to three. Policy and IaC: three to two.
>
> That's **ten effort days handed back to delivery** — plus an estimated monthly cloud saving from the rightsizing patches.
>
> These are honest, internal numbers, not vendor benchmarks. Let me show you it working.

---

## 9 · Live demo — *See it in action* (2:20 — video runs 2:08)

**Before pressing play (10 seconds):**

> This is captured in the live product. Watch for three moments: the six agents finishing in parallel, the **approval** gate, and the **sandbox** proving the fix before the pull request opens.

**▶ Play. Stay silent — the video is narrated.**

**On the last frame (10 seconds):**

> Repository to verified, reviewable pull request — in about two minutes.

---

## 10 · Under the hood — *Proven, open technology* (0:40)

> Nothing here is exotic. React and FastAPI for the experience and platform. CrewAI and a local Gemma 3 model for the intelligence. For evidence: OSV.dev, Trivy-class scanners, radon and ruff, pytest and coverage, Terraform parsing and AWS pricing data.
>
> Open, proven components — the innovation is the **orchestration and the guardrails** around them, not the parts.

---

## 11 · Roadmap — *From hackathon to platform* (0:25)

> **Now**: six agents across Python, JavaScript/TypeScript and Go.
> **Next**: CI-native — scheduled scans and pull-request checks in every pipeline.
> **Later**: read-only live AWS accounts, multi-cloud cost and posture.
> **Vision**: fleet-wide org policy, SLAs and engineering insights.

---

## 12 · Close — *Better. Safer. Cheaper.* (0:15)

> SkyForge AI. Onboard, scan, verify, deliver.
>
> **Better** code, **safer** by design, **cheaper** to run — with a human in the loop at every step.
>
> Thank you. Happy to take questions.

---

## Delivery notes

- **Transitions are written in** — the last line of each slide sets up the next. Don't ad-lib new bridges.
- **Never say "as I mentioned"** — nothing in this script repeats.
- **Don't read animated counters.** Let them land, then speak the takeaway.
- **If you're running long**, cut slide 11 (roadmap) to one line: *"Next is CI-native, then live cloud accounts, then fleet-wide policy."* Saves 20s.
- **If you're running short**, expand slide 8 with: *"The honest caveat is these baselines are ours — your mileage depends on service count and language mix."*
- **Controls:** `←` `→` to navigate, `F` for fullscreen.

## Likely questions (have these ready)

- **"What if the AI's fix is wrong?"** → It never merges. Guardrails validate it, the sandbox has to run it green, and an engineer approves it. Worst case you close a draft PR.
- **"Does our code go to OpenAI?"** → No. The model is Gemma 3 running locally on Ollama. Only the OSV.dev vulnerability lookup leaves the environment, and that's package names and versions.
- **"How do you stop it bumping a dependency and breaking us?"** → Minimal compatible upgrade, then the test suite runs in the sandbox. No green run, no pull request.
- **"Where did 20 days come from?"** → Our own measured effort: ~5 days per 1,000 vulnerabilities, ~3 days to automate unit tests for one service. Happy to share the breakdown.
- **"What languages?"** → Python, JavaScript/TypeScript and Go today, plus Terraform for the cost and IaC agents.

