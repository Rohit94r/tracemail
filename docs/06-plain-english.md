# SecureMailScope — What We Do, in Plain Words
### The no-jargon explainer: what's the problem, how we fix it, and why we're different

Use this on anyone — family, non-technical judges, teammates, an investor. Three layers: a one-liner, a two-minute explanation, and the uniqueness table.

---

## One-Liner (10 seconds)

> "Most of the world's email still travels like an open letter — anyone in the middle can read it. Our tool watches *your* email traffic, checks whether it was actually sealed properly, and gives you a security score plus exactly what to fix."

---

## The Problem (2 minutes, no jargon)

Think of email like a letter sent through thousands of interconnected post offices. The Internet was built ~50 years ago — mail was always meant to be sent as an *open* letter. "Sealing the envelope" (encryption, called TLS) is a *voluntary* extra that each mail server can choose to do.

Today, that system fails in three real ways:

1. **Old, broken post offices.** A lot of servers use ancient, breakable "sealing" — or their identity cards (certificates) are expired or fake. Over a third of the world's mail servers present invalid identity cards.
2. **The seal gets quietly skipped.** A malicious person in the middle can force the postal system to send the letter open, and most servers won't notice or refuse. This actually happened in a whole country once — ~96% of mail got silently downgraded to unsealed.
3. **Nobody watches.** Even big organizations have no idea whether their mail was protected during that day, that month, ever. The service providers won't tell you.

**So:** your email is probably being sent with weak or zero protection, and there is no easy, trustworthy way to find out.

---

## How We Solve It

**What it does:** It's a security camera, not a door-tester. It watches your own email traffic as it flows — the same way a camera at a post office watches the envelopes go through the sorting machine.

**What it sees:** It does **NOT** read your letters. It only looks at the envelope — did the two servers agree to seal it, which level of sealing, and was the "identity card" valid? Then it produces:

- a **score from 0–100** for how safely your email travels,
- a **prioritized list** of problems (most dangerous first),
- **exactly what to fix** (settings to change, in plain language plus copy-paste configs),
- a **report** a security team can keep, audit, and act on.

**The honest part we're proud of:** If the camera can't see something (like a secret envelope type that hides its identity card), we say *"we couldn't verify this"* instead of pretending it's fine. That honesty is rare — and it's what makes the score trustworthy.

---

## How We're Unique (why this isn't "the same as everything else")

| Existing tools / typical contest entries | Us |
|---|---|
| Knock on the server's door to test it (active probing) — NTRO explicitly did NOT want this | We **only watch** your own traffic. Zero touching, zero poking. |
| "Here's a score" (with no proof or uncertainty) | Score with **confidence bounds** + a published formula anyone can check + declared blind spots |
| Check one server at a time | **Whole-picture map**: every server your mail crosses, weakest link highlighted |
| Trust what companies *claim* they do | We **verify claim vs reality** ("we say we enforce sealing → we actually don't") |
| Give a number, no receipts | Every finding points to the **exact packet** of traffic + hash-signed — court/audit-grade evidence |
| Needs the internet to run | **Works fully offline**, air-gapped, reproducible results |

---

## How We're Unique — Even Simpler (for a totally non-technical listener)

> **Everyone else** is like a repairman who knocks on your door to test if it's locked. **We're a security camera** that just watches your own hallway. We never touch anyone.

- **We only watch, never poke.** Other tools test servers by reaching out to them. We silently watch your own traffic. This is what NTRO asked for — and it's the line most rivals cross.
- **We show you how sure we are.** Others print one number like a magic answer. We say "score 82 — but only 70% sure we saw everything, here's what we couldn't see."
- **We look at the whole journey, not one spot.** Your mail passes through many servers. Others check one. We map the whole trip and point at the weakest link.
- **We check promises against reality.** "We use encryption, trust us" — sometimes the actual traffic shows otherwise. We catch that gap.
- **Every answer comes with a receipt.** Click any finding → it shows you the exact moment of traffic it came from. Nothing is a hunch.
- **It runs anywhere.** No internet needed. Works in a locked-down room on a plain laptop.
- **We say "I don't know" when we don't.** Others mark things "fine" to look good. We honestly mark "couldn't verify this part."

---

## Quick Facts to Drop in Conversation (all researched & cited)

- ~30% of the world's email certificates are invalid (mostly wrong hostname).
- ~320,000 mail servers are vulnerable to command injection during the sealing handshake.
- ~41,000 servers were caught actively unsealing email (real-world study).
- Only ~1% of domains enforce modern sealing policies, ~4% use the strongest identity-pinning standard.

*Source: peer-reviewed security research (USENIX, IMC, CCS, NDSS) — full list in `SIH26159-SecureMailScope-Research.md`.*