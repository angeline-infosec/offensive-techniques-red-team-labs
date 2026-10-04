# [SQL Injection Lab](https://tryhackme.com/room/sqlilab) - TryHackMe

_Understand how SQL injection attacks work and how to exploit this vulnerability._

<img width="1902" height="522" alt="image" src="https://github.com/user-attachments/assets/305b59ea-6fd6-4771-9c65-4f53f6c463f6" />


_A hands-on walkthrough of TryHackMe's SQL Injection Lab room — ten challenges spanning classic authentication bypass, UNION-based extraction, boolean-based blind injection, UPDATE-statement injection, second-order (stored) injection, and automated exploitation with sqlmap, including a custom tamper script._

## Lab Overview
This lab worked through ten progressively harder SQL injection scenarios inside a deliberately vulnerable employee-management application. It started with textbook authentication bypass and ended with chained, second-order vulnerabilities that required controlling one query to weaponize a completely different one. Rather than one technique reused ten times, each challenge forced a different angle: reading data out through fields never meant to display it, writing data back through forms assumed to be safe, and exploiting the gap between a query that's correctly parameterized and the one sitting downstream of it that isn't.

I'm working toward a Tier 1 SOC Analyst role, so alongside each technique I've noted what it would actually surface from the defending side — that's ultimately the lens this lab was most useful for.

## What I Learned
**Why string concatenation in SQL queries is the root cause:** every vulnerability in this lab traced back to the same mistake — user input dropped directly into a query string instead of being treated as pure data. The specific syntax varied (login forms, UPDATE statements, search fields), but the underlying flaw never did.

**Why "parameterized" doesn't mean "safe" app-wide:** a query can be perfectly parameterized and still be part of a vulnerable system, if a different, unsafe query later reads the data that safe query stored. Safety is a property of every query touching a piece of data, not of the one that first receives it.

**Why blind injection is slow but not weak:** without any visible output, extracting data one character at a time via true/false responses (or response timing) is tedious by hand — but it's just as complete as reading data directly off the page, and it's exactly what tools like sqlmap exist to automate.

## Investigation Steps

### Step 1 — Environment Setup & Baseline Bypass | ⚙️ Prerequisite
**What happened:**
The sandbox app runs with a "Show Query" toggle exposing the live SQL behind every request — genuinely useful for confirming cause and effect rather than guessing. Starting with the simplest login forms, an integer-type parameter and a string-type parameter each fell to the classic always-true bypass:
```
1 or 1=1-- -
1' or '1'='1'-- -
```
One early snag: a bare `--` comment marker didn't reliably work. MySQL's comment syntax requires a trailing whitespace character after the second dash to actually take effect — without it, a stray quote left over from the original query can go unmatched and break the injection instead of completing it. Switching to `-- -` (dash-dash-space-dash) fixed it immediately.

_[Screenshot: login bypass with Show Query panel confirming the injected statement]_

**Why this matters:**
This is the foundational pattern every later challenge in the lab builds on — close the data context you've been placed in, inject a condition, comment out the rest. Getting the comment syntax wrong looks like a failed injection, not a syntax issue, which is a useful debugging lesson on its own.

**Flags:** `THM{dccea429d73d4a6b4f117ac64724f460}`, `THM{356e9de6016b9ac34e02df99a5f755ba}`

---

### Step 2 — Defeating Client-Side Controls | 🧱 Bypass Technique
**What happened:**
The next two forms added JavaScript restricting input to alphanumeric characters. For the GET-based form, the client-side check was skipped entirely by crafting the target URL directly in the address bar — the JS never runs if the form itself is never submitted through the browser's normal flow. For the POST-based form, that wasn't an option, so I intercepted the request in **Burp Suite** and edited the raw request body before forwarding it. The same comment-syntax issue from Step 1 reappeared here — a bare `--` silently failed inside Burp until I added the trailing space back in. Once the login succeeded, I captured the resulting session cookie and replayed it with Burp Repeater against the application's home page to pull the flag straight out of the rendered HTML.

_[Screenshot: Burp Repeater request/response showing the authenticated home page and flag]_

**Why this matters:**
Client-side validation is a UX feature, not a security boundary — the client is fully under the attacker's control, whether that's a crafted URL or an intercepting proxy. From a defensive standpoint, any server-side endpoint that *only* trusts JS-level input filtering has no real protection at all.

**Flags:** `THM{645eab5d34f81981f5705de54e8a9c36}`, `THM{727334fd0f0ea1b836a8d443f09dc8eb}`

---

### Step 3 — UPDATE-Statement Injection: Read and Write | ✍️ Key Finding
**What happened:**
A profile-edit form updating a nickname and email field turned out to route injected SQL into fields that get rendered straight back to the user on the next page load — turning an `UPDATE` statement, normally a dead end for reading data, into a usable extraction channel. After confirming the vulnerability, I fingerprinted the database engine with `sqlite_version()`, then used SQLite's `sqlite_master` table — its equivalent of `information_schema` — to enumerate every table and column in the database:
```sql
',nickName=(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'),email='
```
With the schema mapped, I dumped the full user table via `group_concat()`, identified the password hash format as SHA-256, cracked one hash to confirm correctness against a known login, then generated a fresh SHA-256 hash for a chosen password and wrote it directly into the admin account's password field through the same injection point.

_[Screenshot: profile page displaying the dumped user table via the nickName field]_
_[Screenshot: admin account access confirmed after the password overwrite]_

**Why this matters:**
This step moved past reading data and into full account takeover via a write operation — a meaningfully worse outcome than a typical read-only SQLi finding. From a monitoring standpoint, any `UPDATE`/`INSERT` endpoint deserves the same scrutiny as a `SELECT`-heavy one; an unusually long or structured value landing in a field meant to hold a short nickname is a strong anomaly signal worth alerting on.

**Flag:** `THM{b3a540515dbd9847c29cffa1bef1edfb}`

---

### Step 4 — UNION-Based Extraction | 🔍 Reconnaissance
**What happened:**
A second application track started with the same authentication bypass, confirming the pattern transfers across different codebases. The next challenge required dumping every password in the database without relying on blind techniques. I used UNION-based injection, first determining the original query's column count by incrementing `NULL` placeholders until the login succeeded, then substituting a real extraction query once the shape matched:
```sql
' UNION SELECT 1,group_concat(password) FROM users-- -
```
The dumped data appeared both directly on the page and inside the application's Flask session cookie, which I decoded separately to confirm — session tokens can end up carrying more than developers intend if query output gets stored in them.

_[Screenshot: decoded session cookie showing the dumped password data]_

**Why this matters:**
UNION-based injection is the loudest, fastest category to exploit — but also the easiest to catch, since the attacker needs the response to visibly change in a specific, predictable way. It's a good baseline before moving into techniques designed to avoid exactly that kind of visibility.

**Flags:** `THM{f35f47dcd9d596f0d3860d14cd4c68ec}`, `THM{fb381dfee71ef9c31b93625ad540c9fa}`

---

### Step 5 — Boolean-Based Blind Injection & Automation | 🕵️ Advanced Technique
**What happened:**
This challenge removed all visible output — no page content changes, no useful session data, just a login that succeeds or fails. I extracted the admin password one character at a time using `SUBSTR()` combined with hex-encoded character comparisons, which was necessary because the application lowercases input server-side, breaking a naive direct-string comparison:
```sql
admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1) = CAST(X'54' as Text)-- -
```
I automated the extraction with **sqlmap** rather than scripting it by hand. The documented default command didn't reliably detect the injection point on its own — explicitly targeting the parameter (`-p username`) and giving sqlmap a clear true/false oracle (`--not-string="Invalid"`) was what got it working:
```bash
sqlmap -u "http://<ip>:5000/challenge3/login" \
  --data="username=admin&password=admin" \
  --level=5 --risk=3 --dbms=sqlite --technique=B \
  -p username --not-string="Invalid" --dump
```

_[Screenshot: sqlmap confirming the boolean-based blind injection point and dumping the flag]_

**Why this matters:**
Blind injection is slow precisely because it needs one request per character guessed — and that's exactly what makes it detectable. A string of dozens or hundreds of near-identical requests hitting the same login endpoint in a short window, each differing by one or two characters, is a distinctive volume pattern that's often easier to catch in logs than trying to parse payload content directly.

**Flag:** `THM{f1f4e0757a09a0b87eeb2f33bca6a5cb}`

---

### Step 6 — Second-Order (Stored) Injection | 🪤 Critical Finding
**What happened:**
This was the most interesting vulnerability in the lab. The application's note-insertion query was correctly **parameterized** — the query structure was fixed first, with user input bound in afterward purely as data, never as executable SQL. That makes it genuinely safe from injection at that point. The catch: a completely different query, responsible for *reading* notes back, concatenated the stored username directly:
```sql
SELECT title, note FROM notes WHERE username = '" + username + "'
```
A malicious username, safely stored at registration, became a live injection point the moment that account's own Notes page loaded — the vulnerability didn't fire at write time, only on a later, unrelated read. I registered a sequence of malicious usernames to enumerate the schema and ultimately dump the password table, with the actual injection triggering only once I logged in and visited Notes as each account:
```sql
' union select 1,group_concat(password) from users'
```
I also worked out (though didn't execute live) how this would be automated with sqlmap: since the injection point (registration) and the vulnerable read (Notes page) are two separate requests, it requires a custom tamper script that registers an account, logs in, and injects the resulting session cookie into the next request's headers — letting sqlmap chain all three steps per payload attempt.

_[Screenshot: Notes page displaying the dumped password data]_

**Why this matters:**
This is the clearest example in the lab of why "we use parameterized queries" isn't a complete answer to "are we safe from SQL injection." It has to hold true for *every* query that ever touches a given piece of data, not just the first one. It also argues for validating or sanitizing stored data at write time regardless of how safely it was written, since you can't guarantee every future read path will be equally careful.

**Flag:** `THM{4644c7e157fd5498e7e4026c89650814}`

---

### Step 7 — Trusted-Data Injection | 🔑 Logic Flaw
**What happened:**
A password-change feature correctly parameterized the new password value, but concatenated the username — fetched from the session rather than directly from user input — on the assumption that session-sourced data was inherently safe. It wasn't: that username had originally been set by the user at registration, meaning it was attacker-controlled from the start, just several steps removed. Registering as `admin'-- -`, then changing *that* account's own password, caused the resulting `UPDATE` to land on the real `admin` account instead — the injected comment stripped the rest of the intended `WHERE` condition.

_[Screenshot: successful login as admin after the password overwrite, showing the flag]_

**Why this matters:**
The useful general principle here: where a value currently lives (session, database, request body) matters less than whether it was ever attacker-influenced at any point in its history. "It's not raw user input" is not the same claim as "it's safe."

**Flag:** `THM{cd5c4f197d708fda06979f13d8081013}`

---

### Step 8 — Chained Query Exploitation | 🔗 Advanced Technique
**What happened:**
A book-search feature concatenated search input directly into a `LIKE` clause, giving a straightforward UNION-based dump once the column count was matched. A follow-up challenge raised the difficulty by chaining two independently vulnerable queries — the first fetches a book's ID, the second uses that ID in a completely separate query. Rather than attacking either one blind, I forced the first query to return zero real rows, controlled its output directly, and fed a crafted value into the second query. To get the second query to run its own UNION rather than just accept a literal value, I had to escape into it by doubling the single quote (`''`) to correctly terminate the string literal the first injection had opened:
```sql
' union select '-1'' union select 1,2,group_concat(password),4 from users-- -
```

_[Screenshot: search results displaying the final dumped password data]_

**Why this matters:**
Chained, second-order-style vulnerabilities like this one are genuinely harder to catch with simple single-request pattern matching, since no individual request looks obviously malicious on its own — it's the sequence across requests that matters. This is a solid argument for correlating application logs across a session rather than evaluating each request in isolation.

**Flags:** `THM{27f8f7ce3c05ca8d6553bc5948a89210}`, `THM{183526c1843c09809695a9979a672f09}`

## Key Takeaways
- Parameterized queries are necessary but not sufficient — every query touching a given piece of data needs the same discipline, not just the one that first receives it.
- "Safe because it came from the database or session, not directly from user input" is a trap — if a value was ever attacker-controlled upstream, it's still attacker-controlled.
- Blind and second-order injection are slower and noisier to exploit by hand, but that noise — request volume, request sequencing — is exactly what makes them detectable from the defensive side, even without inspecting payload content directly.
- Automated tooling isn't plug-and-play. Getting sqlmap to actually find and exploit some of these vulnerabilities required understanding the underlying technique well enough to steer it — explicit parameter targeting, custom success/failure strings, and for the stored-injection case, a custom tamper script to chain a multi-step exploit.

## Skills Practiced
- SQL injection: classic, UNION-based, boolean-based blind, UPDATE-statement, and second-order/stored
- Client-side control bypass via direct URL manipulation and Burp Suite request interception
- Database schema enumeration via SQLite's `sqlite_master` table
- Hash identification and cracking (SHA-256)
- Session cookie analysis and decoding (Flask sessions)
- Automated exploitation and custom tamper script development with sqlmap

## Tools & Technologies
- **Burp Suite** – intercepting and modifying POST requests to bypass client-side validation
- **sqlmap** – automated boolean-based blind injection and second-order injection via custom tamper scripts
- **CyberChef** – generating SHA-256 hashes for credential overwrite
- **Flask session decoder** – inspecting session cookie contents for leaked query data
- **SQLite** – target database engine throughout the lab

## Conclusion
No single technique in this lab was exotic — every vulnerability traced back to the same root cause of unsanitized string concatenation. What made the later challenges genuinely difficult wasn't the SQL itself, but recognizing *where* that concatenation was happening: not always in the form directly in front of me, but sometimes in a completely different query, triggered by a completely different request, reading data that had been safely stored much earlier. That gap — between where a payload is planted and where it actually detonates — is the part of SQL injection that's easiest to underestimate, and the part most worth understanding well before moving into any defensive role meant to catch it.
