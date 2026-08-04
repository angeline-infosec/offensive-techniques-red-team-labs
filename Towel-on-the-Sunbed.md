# Towel on the Sunbed - [TryHackMe Hacker's Holiday 2026](https://tryhackme.com/hackerholidays)

**Room:** [Towel on the Sunbed (TryHackMe Hacker's Holiday 2026)](https://tryhackme.com/room/hh-towelonthesunbed-61271709)

**Category:** Business Logic / API Abuse

**Vulnerability class:** Race Condition (TOCTOU) — CWE-362

---

## Scenario

Ponzi Portfolio is a wellness-resort crypto rewards app. Guest accounts start at 0 PONZI and can claim a 50-PONZI staking reward once every 24 hours. Hitting 150 PONZI unlocks the "Whale Vault" and its reward — at the intended pace that's three separate days of claiming. The goal was to reach Whale tier without actually waiting three days.

## First attempt (and the wall I hit)

I registered a guest account (`test` / `testuser`) and landed on the dashboard: 0 PONZI, Shrimp tier, Whale Vault locked at 150/150, and a Claim Reward button as the only interactive piece on the page. I checked the page source and `dashboard.js` first, just to see if there was anything obvious client-side — there wasn't, it was purely UI rendering, so I moved on.

I fired up Burp, intercepted the claim request, and sent it to Repeater. First send worked fine — 50 PONZI, still Shrimp tier. Out of curiosity I hit send again on the exact same request, and that's where the 24-hour lockout kicked in — the app told me to come back tomorrow. So the server side clearly does check some kind of "last claimed at" timestamp before it lets a claim through.

At that point sequential requests were a dead end on this account (I'd already burned my one claim for the day), so I logged out and registered a fresh account, `test` / `testing`, to start clean and actually try to break the timing instead of just confirming it existed.

## The actual move

Request captured, looked like this:

```
POST /claim HTTP/1.1
Host: <target>:3000
Cookie: connect.sid=<session>
Content-Length: 0
```

The lockout behavior from my first account told me the check is something like: look up `last_claim_timestamp`, if less than 24h ago reject, otherwise credit 50 PONZI and update the timestamp. Sending requests one after another (even fast, by hand) always lets the first one fully complete — write included — before the second even lands. So a normal Repeater retry will always get caught by the check, same as it did on account one.

The gap that matters is between the server *reading* the timestamp and the server *writing* the new one. If two or more requests land in that gap at the same time, they can all read "not claimed yet" before any of them has saved the update.

So on the new account I duplicated the claim request into a Repeater group of 3 and used **Send group in parallel**, which pushes all of them out close to simultaneously instead of one after another. All three landed inside that check-to-write gap and all three went through:

```json
{"message":"Staking reward claimed successfully.","reward":50,"newBalance":150,"tier":"Whale","priceSnapshot":4.2}
```

0 → 150 PONZI in one burst. Refreshed the dashboard, Whale tier unlocked, vault open.

**Flag:** `THM{t0w3l_0n_th3_sunb3d_d0ubl3_sp3nt}`

## Vulnerability classification

MITRE ATT&CK doesn't really apply here — it's built around adversary behavior against infrastructure, not app-level logic bugs, so trying to force a technique ID onto this would be a stretch. The honest reference points are:

- **CWE-362** — Concurrent Execution using Shared Resource with Improper Synchronization ("Race Condition")
- **OWASP API Security Top 10 (2023) — API8:2023** — Security Misconfiguration / Lack of Resources & Rate Limiting, which overlaps with the fix here
- Business Logic Vulnerabilities more broadly, per OWASP

## How I'd fix it

- Make the check and the update one atomic operation — a DB transaction with row locking (`SELECT ... FOR UPDATE`), or a conditional update like `UPDATE ... WHERE last_claim < now() - interval '24 hours'` that can only succeed for one of the concurrent requests.
- A unique constraint (one claim record per account per day) would also work — the second concurrent insert just fails.
- Rate limiting on its own doesn't fix this. It slows down how often you *can* request, but three requests sent in the same millisecond are all still "within the rate limit" — the race window is still there.

## What I learned

- The bug isn't in what the endpoint does, it's in the timing of when it does it. Anywhere there's a read-then-write on a per-user resource without locking, that gap is exploitable.
- My first account taught me something useful even though it "failed" — confirming the sequential lockout is what told me the timestamp check exists and that I needed simultaneous requests, not repeated ones.
- This class of bug won't show up from clicking around the UI or reading client-side JS — it only shows up under real concurrency, which is why the tool matters (Burp's parallel send here, Turbo Intruder for cases that need single-packet precision).
- Knowing when *not* to force a MITRE ATT&CK mapping is its own skill — CWE/OWASP fit app logic flaws better, and picking the right framework says more in an interview than a wrong mapping would.


## Q&A

**Q: What is a race condition and why is it a security issue?**
A: It happens when a system's correctness depends on the order or timing of concurrent operations. In web apps this usually shows up as a check (is this allowed?) and a write (do it, record that it happened) that aren't atomic — enough requests hitting that gap at once can all pass the check before any of them commits the write.

**Q: How do you test for one?**
A: Find any endpoint enforcing a one-time action or limit — claims, coupon redemption, balance transfers, vote/like actions — and send several identical authenticated requests as close to simultaneously as possible. Burp's "Send group in parallel," Turbo Intruder's single-packet attack, or a small async script all work. Then check if the limit got exceeded.

**Q: How would you fix this one specifically?**
A: Collapse the check and the update into a single atomic DB operation — transaction with row locking, or a conditional update that only one concurrent request can satisfy.

**Q: Why doesn't rate limiting solve it?**
A: Rate limiting caps how often requests are allowed over time, not what happens when several already-allowed requests arrive at the same instant. They can all be within the limit and still all win the race.

