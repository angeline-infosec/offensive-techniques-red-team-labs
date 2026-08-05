# Towel on the Sunbed - [TryHackMe Hacker's Holiday 2026](https://tryhackme.com/hackerholidays)

**Room:** [Towel on the Sunbed (TryHackMe Hacker's Holiday 2026)](https://tryhackme.com/room/hh-towelonthesunbed-61271709)

**Category:** Business Logic / API Abuse

**Vulnerability class:** Race Condition (TOCTOU) — CWE-362

<img width="1908" height="532" alt="image" src="https://github.com/user-attachments/assets/860ec183-9387-4801-8b52-d2257bf0783b" />


---

## Scenario

Ponzi Portfolio is a wellness-resort crypto rewards app. Guest accounts start at 0 PONZI and can claim a 50-PONZI staking reward once every 24 hours. Hitting 150 PONZI unlocks the "Whale Vault" and its reward. At the intended pace that's three separate days of claiming. The goal was to reach Whale tier without actually waiting three days.

## First attempt (and the wall I hit)

I registered a guest account (`test` / `testuser`) and landed on the dashboard: 0 PONZI, Shrimp tier, Whale Vault locked at 150/150, and a Claim Reward button as the only interactive piece on the page. I checked the page source and `dashboard.js` first, just to see if there was anything obvious client-side but there wasn't; it was purely UI rendering, so I moved on.

<img width="1920" height="953" alt="register" src="https://github.com/user-attachments/assets/937037b8-5022-4a71-b9f6-fabb9445914c" />

<img width="1920" height="962" alt="dashboard" src="https://github.com/user-attachments/assets/5dad114b-f9bd-4dfd-a390-2c768100f4f6" />


I opened Burp, intercepted the claim request, and sent it to Repeater. First send worked fine. 50 PONZI but still Shrimp tier. Out of curiosity, I hit send again on the exact same request, and that's where the 24-hour lockout kicked in, the app told me to come back tomorrow. So the server side clearly does check some kind of "last claimed at" timestamp before it lets a claim through.

<img width="1196" height="615" alt="Burp req 2" src="https://github.com/user-attachments/assets/a6961618-6922-4fb9-a46c-00990ac1c507" />


At that point, sequential requests were a dead end on this account (I'd already burned my one claim for the day), so I logged out and registered a fresh account, using credentials `test` / `testing`, to start clean and actually try to break the timing instead of just confirming it existed.

## The actual move

My first account showed that the server's logic is probably:
* Read the user's last_claim_timestamp.
* If the last claim was less than 24 hours ago, reject the request.
* Otherwise, award 50 PONZI and update last_claim_timestamp.

So, sending requests sequentially won't trigger the vulnerability because the first request finishes updating the timestamp before the next request begins. The vulnerable window exists between the server reading the current timestamp and writing the updated one. If multiple requests are processed concurrently during that interval, they can all observe the old value, pass the eligibility check, and each receive the reward before the timestamp is updated. This is the race condition being exploited.

So, on the new account, I duplicated the claim request into a Repeater group of 3 and used **Send group in parallel**, which pushes them out close to simultaneously rather than one after another. All three landed inside that check-to-write gap and all three went through:

<img width="948" height="486" alt="request grouped" src="https://github.com/user-attachments/assets/79b80e3b-c57a-4715-8ba7-86af4a67873e" />


<img width="1194" height="616" alt="Tier Whale access" src="https://github.com/user-attachments/assets/2c6eb02f-7640-4ea3-a278-4bf7f776b06e" />


```json
{
"message":"Staking reward claimed successfully.",
"reward":50,
"newBalance":150,
"tier":"Whale",
"priceSnapshot":4.2
}
```

0 → 150 PONZI in one burst. I turned off intercept and proxy, refreshed the dashboard, Whale tier unlocked, and the vault opened with the flag of the room.

<img width="1920" height="960" alt="Flag" src="https://github.com/user-attachments/assets/941635f2-aa76-434c-914d-e00ba5fc8365" />


**Flag:** `THM{t0w3l_0n_th3_sunb3d_d0ubl3_sp3nt}`


## How I'd fix it

From what I observed, the problem is that the application checks whether a user can claim the reward and updates the claim timestamp as two separate steps. Because those steps aren't atomic, multiple requests can pass the check before the timestamp is updated.

A few ways this could be fixed are:

* Wrap the check and update in a single database transaction (for example, using SELECT ... FOR UPDATE) so only one request can process the claim at a time.
* Use a conditional database update that only succeeds if the previous claim was more than 24 hours ago. If another request has already updated the record, the second update simply fails.
* Store each claim as a separate database record with a unique constraint (for example, one claim per account per day). Concurrent requests would cause only one insert to succeed while the others would be rejected.

Simply adding rate limiting wouldn't solve this issue. The problem isn't how many requests are sent over time. It is that several requests can reach the server at nearly the same moment and all pass the eligibility check before the database is updated.

Ps. I couldn't confirm the exact backend implementation because I didn't have access to the source code. These are the mitigations I would expect for this type of race condition.

## What I learned

- Before this room, I understood race conditions conceptually but hadn't exploited one myself. What stood out was that the application behaved correctly under normal usage. The vulnerability only appeared when multiple requests were processed concurrently. It reinforced that security testing isn't just about manipulating input, sometimes it's about manipulating timing.
- The bug isn't in what the endpoint does, it's in the timing of when it does it. Anywhere there's a read-then-write on a per-user resource without locking, that gap is exploitable.
- My first account taught me something useful even though it failed. It confirmed the sequential lockout is what told me the timestamp check exists and that I needed simultaneous requests, not repeated ones.
- This class of bug won't show up from clicking around the UI or reading client-side JS, it only shows up under real concurrency, which is why the tool matters (Burp's parallel send here).

---

## Q&A

**Q: What is a race condition and why is it a security issue?**
A: It happens when a system's correctness depends on the order or timing of concurrent operations. In web apps this usually shows up as a check (is this allowed?) and a write (do it, record that it happened) that aren't atomic — enough requests hitting that gap at once can all pass the check before any of them commits the write.

**Q: How do you test for one?**
A: Find any endpoint enforcing a one-time action or limit — claims, coupon redemption, balance transfers, vote/like actions — and send several identical authenticated requests as close to simultaneously as possible. Burp's "Send group in parallel," Turbo Intruder's single-packet attack, or a small async script all work. Then check if the limit got exceeded.

**Q: How would you fix this one specifically?**
A: Collapse the check and the update into a single atomic DB operation — transaction with row locking, or a conditional update that only one concurrent request can satisfy.

**Q: Why doesn't rate limiting solve it?**
A: Rate limiting caps how often requests are allowed over time, not what happens when several already-allowed requests arrive at the same instant. They can all be within the limit and still all win the race.

