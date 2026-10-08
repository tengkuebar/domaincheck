---
name: plain-writing
description: Writing rules for everything a person reads in DomainCheck - the README, docs, report text, fix-step JSON, error messages, UI copy and commit or PR descriptions. Use this whenever you write or edit prose in this project, review text for filler or AI-sounding phrasing, or the user says "tighten this", "make it plainer", "stop-slop" or asks for README, docs or user-facing wording, even if they do not name the style.
---

# Plain writing

The readers are a small business owner who is not a security expert, and a recruiter or interviewer
skimming the repo. Both want to know what is true, what to do, and where the limits are, in that
order. Slop (filler, hype, vague claims) costs them time and makes real warnings harder to trust.
These rules keep the text short and honest.

## Rules

1. **Lead with the answer.** The first sentence says what the thing is or what to do. Context comes after.
2. **Short, plain words.** "Use", not "utilise". "Check", not "leverage". If a technical term is
   needed, say what it means the first time ("DMARC, which tells receivers what to do with forged mail").
3. **Say what it cannot do.** A limit stated plainly is more credible than a feature list. Never claim
   more than was tested ("Works" means a test or a real run showed it).
4. **Concrete beats vague.** Give the number, name, command or file. "Fix in about 10 minutes" over
   "quick to fix". "TLS 1.0 and 1.1 are still accepted" over "outdated protocols detected".
5. **No filler.** Cut openers ("In today's world", "It's important to note that"), closers ("I hope this
   helps", "Let me know if..."), and sentences that only announce the next sentence.
6. **No hype or empty adjectives.** Avoid: robust, seamless, powerful, comprehensive, cutting-edge,
   leverage, delve, streamline, game-changing, "best-in-class". If a quality matters, show the evidence.
7. **No tidy-sounding patterns.** Watch for "not just X, but Y", lists of exactly three adjectives,
   a one-line paragraph that restates the point, and em dashes used as a tic. Use a full stop or a colon.
8. **Tell people what to do, not just what is wrong.** Every warning or error ends with the next step.
   Say why only if it changes the decision.
9. **Status is words, not colour or symbols alone.** "Fix now", "Improve", "Good".
10. **Plain voice for people.** Address the reader as "you". Active verbs. Avoid "we" for the
    software when "it" is clearer; avoid blame ("you failed to").
11. **Never state secrets or internals.** User-facing errors stay generic; details go to logs.

## Where it applies

| Text | Extra guidance |
|---|---|
| Report findings and fix steps | One idea per sentence. Name the setting or record to change. Mention that provider screens change. |
| Error messages | What happened, what to do. No exception text. |
| README | What it does, how to run it, what it cannot do, how it is secured. Screenshots say what data they show. |
| Commit and PR text | What changed and why, in two or three lines. |

## Before and after

| Before | After |
|---|---|
| "DomainCheck is a powerful, comprehensive solution that seamlessly leverages best practices to empower you." | "DomainCheck checks a domain's email and website security and gives you fix steps." |
| "It's important to note that DKIM selectors can't be discovered, so results may vary." | "DKIM 'not detected' only means not found under the names we try. Your provider may use another." |
| "An error occurred while processing your request." | "The check failed. Please try again." |
| "Consider potentially reviewing your SPF configuration." | "Add one SPF record at the root of your domain." |
| "Robust security headers are not implemented." | "Missing: Content-Security-Policy, Referrer-Policy, Permissions-Policy." |

## Self-check before finishing

- Could any sentence be deleted without losing information? Delete it.
- Is every claim backed by a test, a run, or the code? If not, soften it or remove it.
- Would a non-expert know what to do after reading this?
- Search the text for the banned words in rule 6 and for em dashes.
