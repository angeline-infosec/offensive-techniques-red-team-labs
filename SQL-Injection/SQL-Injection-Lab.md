# [SQL Injection Lab](https://tryhackme.com/room/sqlilab) - TryHackMe

_Understand how SQL injection attacks work and how to exploit this vulnerability._

<img width="1902" height="522" alt="image" src="https://github.com/user-attachments/assets/305b59ea-6fd6-4771-9c65-4f53f6c463f6" />


_A hands-on walkthrough of TryHackMe's SQL Injection Lab room — ten challenges spanning classic authentication bypass, UNION-based extraction, boolean-based blind injection, UPDATE-statement injection, second-order (stored) injection, and automated exploitation with sqlmap, including a custom tamper script._



## Environment

A standalone sandbox app at `http://<machine_ip>:5000`, with a "Show Query" toggle to see the live SQL being executed and a "Guidance" toggle for hints. Split into two tracks: **Introduction to SQL Injection** (5 isolated challenges building up core technique) and **Vulnerable Startup** (a themed employee-management app with progressively realistic, chained vulnerabilities).

---

## Track 1: Introduction to SQL Injection

### Challenges 1–2: Classic Authentication Bypass
Two login forms, one taking an integer `profileID`, one taking a string. The core idea is the same either way — inject a condition that's always true, then comment out whatever's left of the original query:
```
1 or 1=1-- -              (integer parameter)
1' or '1'='1'-- -          (string parameter)
```
One detail worth knowing: MySQL's `--` comment marker needs a trailing whitespace character to actually take effect — a bare `--` with nothing after it can leave a stray quote unmatched and break the query instead of commenting it out cleanly. `-- -` (dash-dash-space-dash) sidesteps that, and survives URL-encoding intact too.

**Flags**: `THM{dccea429d73d4a6b4f117ac64724f460}`, `THM{356e9de6016b9ac34e02df99a5f755ba}`

### Challenges 3–4: Bypassing Client-Side Validation
Both forms add JavaScript restricting input to alphanumeric characters only. Client-side validation is a UX feature, not a security boundary — the client is fully under the attacker's control.
- **Challenge 3** (GET request): bypassed entirely by crafting the URL directly — `?profileID=-1' or 1=1-- -&password=a` — skipping the form (and its JS) altogether.
- **Challenge 4** (POST request): required intercepting the request in **Burp Suite** and editing the raw body before forwarding. First attempt failed silently — a bare `--` left a trailing `'` from the original query unmatched, same root cause as the comment-syntax note above. Fixing it to `-- ` (trailing space) resolved it. Captured the resulting session cookie and replayed it via Repeater against `/home` to pull the flag straight out of the rendered page.

**Flags**: `THM{645eab5d34f81981f5705de54e8a9c36}`, `THM{727334fd0f0ea1b836a8d443f09dc8eb}`

**Detection angle**: both bypass techniques leave `OR 1=1`, stray `'`/`--` sequences, or unexpected special characters sitting in URL parameters and POST bodies — exactly the kind of signature a WAF rule or a simple regex-based log alert on login endpoints should be catching.

### Challenge 5: UPDATE-Statement Injection
A profile-edit form updating `nickName`/`email` turned out to route injected SQL into fields that get rendered straight back to the user — meaning an `UPDATE` statement became a usable (if unconventional) data-extraction channel. Confirmed the vulnerability, fingerprinted the DB engine (`sqlite_version()`), then used SQLite's `sqlite_master` table (its equivalent of `information_schema`) to enumerate tables and columns:
```sql
',nickName=(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'),email='
```
Dumped the `usertable` contents via `group_concat()`, identified the password hashes as SHA-256, cracked one to confirm it matched a known login (`toor`), then generated a new SHA-256 hash via CyberChef and wrote it directly to the admin account's password field through the same injection point — gaining full account takeover via a write, not just a read.

**Flag**: `THM{b3a540515dbd9847c29cffa1bef1edfb}`

**Detection angle**: this one's a good reminder that SQLi monitoring shouldn't only watch `SELECT`-heavy endpoints — any form submitting to an `UPDATE` or `INSERT` path deserves the same input-validation logging. An UPDATE with abnormal payload length or embedded subqueries in a field expected to be a short string (like a nickname) is a strong anomaly signal.

---

## Track 2: Vulnerable Startup

### Broken Authentication → Broken Authentication 2
Same core bypass (`' or 1=1-- -`) got me in anonymously first. The next challenge asked for a full password dump without relying on blind techniques — solved with UNION-based injection, first confirming the query's column count by incrementing `NULL` placeholders, then substituting a real extraction query once the shape matched:
```sql
' UNION SELECT 1,group_concat(password) FROM users-- -
```
The dumped data showed up both directly on the page and inside the decoded Flask session cookie — a good reminder that session tokens can carry more than developers intend if query results get stuffed into them.

**Flags**: `THM{f35f47dcd9d596f0d3860d14cd4c68ec}`, `THM{fb381dfee71ef9c31b93625ad540c9fa}`

### Broken Authentication 3: Blind Injection
No visible output this time — just a login that succeeds or fails. Extracted the admin password one character at a time using `SUBSTR()` combined with hex-encoded character comparisons (needed because the app lowercases input server-side, which breaks a naive direct-string comparison):
```sql
admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1) = CAST(X'54' as Text)-- -
```
Ran this against the target with **sqlmap** rather than by hand. The default command from the room's own documentation didn't reliably detect the injection point — explicitly targeting the parameter (`-p username`) and giving sqlmap a clear true/false oracle (`--not-string="Invalid"`) is what got it working:
```bash
sqlmap -u "http://<ip>:5000/challenge3/login" \
  --data="username=admin&password=admin" \
  --level=5 --risk=3 --dbms=sqlite --technique=B \
  -p username --not-string="Invalid" --dump
```

**Flag**: `THM{f1f4e0757a09a0b87eeb2f33bca6a5cb}`

**Detection angle**: boolean/time-based blind injection is slow precisely because it needs one request per character guessed — which means it leaves a very distinctive trace in web server logs: dozens to hundreds of near-identical requests to the same endpoint in a short window, differing by one or two characters each time. That request-volume pattern is often easier to catch than trying to parse the payloads themselves.

### Vulnerable Notes — Second-Order (Stored) Injection
This one was the most interesting of the room. The note-insertion query was properly **parameterized** — the query structure is written first with `?` placeholders, and user input is only ever bound in afterward as pure data, never as part of the SQL itself. That makes it genuinely safe from injection *at that point*.

The catch: parameterized queries stop malicious input from executing, but they don't stop it from being *stored*. The query that later *reads* notes back concatenated the username directly:
```sql
SELECT title, note FROM notes WHERE username = '" + username + "'
```
So a malicious username, safely stored at registration, became a live injection point the moment that account's own Notes page was loaded — the vulnerability doesn't fire until a *second*, unrelated query reads the poisoned data back. Registered a sequence of malicious usernames to enumerate the schema and ultimately dump the password table, triggering the actual injection on each subsequent login + page visit:
```sql
' union select 1,group_concat(password) from users'
```

**Flag**: `THM{4644c7e157fd5498e7e4026c89650814}`

**Detection angle**: this is exactly why "we use parameterized queries" isn't a complete answer to "are we safe from SQLi" — it has to be true for *every* query touching that data, not just the one that first receives it. From a monitoring standpoint, this also argues for validating/sanitizing stored data at write time regardless of how safely it was written, since you can't always guarantee every future read path will be equally careful.

### Change Password — Trusted-Data Injection
A password-change feature parameterized the new password correctly, but concatenated the username — fetched from the session, not directly from user input — on the (incorrect) assumption that session-sourced data was inherently safe. It wasn't: that username had originally been set by the user at registration. Registering as `admin'-- -`, then changing *that* account's own password, caused the resulting `UPDATE` to land on the real `admin` account instead, due to the comment stripping the rest of the intended `WHERE` condition.

**Flag**: `THM{cd5c4f197d708fda06979f13d8081013}`

**Detection angle**: a useful general principle — "where did this data come from" matters less than "has this specific value ever been attacker-influenced at any point." Session-sourced data isn't automatically trustworthy just because it didn't arrive in the current request's raw input.

### Book Title & Book Title 2 — UNION Injection and Query Chaining
A book-search feature concatenated search input into a `LIKE` clause, allowing a straightforward UNION-based dump once the column count was matched:
```sql
') UNION SELECT 1,2,3,group_concat(password) FROM users-- -
```
The follow-up challenge chained two separate, independently vulnerable queries — the first fetches a book ID, the second uses that ID in its own query. Rather than attacking either one blind, I controlled the first query's output directly, fed a crafted value into the second, and escaped into a second UNION by doubling the single quote (`''`) to properly terminate the string the first injection had opened:
```sql
' union select '-1'' union select 1,2,group_concat(password),4 from users-- -
```

**Flags**: `THM{27f8f7ce3c05ca8d6553bc5948a89210}`, `THM{183526c1843c09809695a9979a672f09}`

**Detection angle**: chained/second-order vulnerabilities like this one are genuinely harder to catch with simple pattern matching on a single request, since no single request looks obviously malicious in isolation — it's the sequence across requests that matters. This is a solid argument for correlating application logs across a session rather than evaluating each request independently.

---

## Takeaways

- Parameterized queries are necessary but not sufficient — every query touching a given piece of data needs the same discipline, not just the one that first receives it.
- "Safe because it came from the database/session, not directly from the user" is a trap — if that value was ever attacker-controlled upstream, it's still attacker-controlled.
- Blind and second-order injection are slower and noisier to exploit by hand, but that noise (request volume, request sequencing) is exactly what makes them detectable from the defensive side, even without inspecting payload content directly.
- Tooling (sqlmap) isn't plug-and-play — getting it to actually find and exploit some of these vulnerabilities required understanding the underlying technique well enough to steer it (explicit parameter targeting, custom success/failure strings, and for the stored-injection case, a custom tamper script to chain a multi-step exploit).
