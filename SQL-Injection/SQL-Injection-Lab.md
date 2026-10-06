# [SQL Injection Lab](https://tryhackme.com/room/sqlilab) - TryHackMe

Room: [SQL Injection Lab](https://tryhackme.com/room/sqlilab)

Category: Web Exploitation

Vulnerability class: SQL Injection (classic, UNION-based, boolean-based blind, UPDATE-statement, second-order/stored) - related to OWASP A03: Injection

<img width="1902" height="522" alt="image" src="https://github.com/user-attachments/assets/305b59ea-6fd6-4771-9c65-4f53f6c463f6" />


## Scenario

This room is a standalone SQL injection sandbox split into two tracks. The first is a straight-up intro to the technique: five challenges that build the core skill one piece at a time. The second drops you into a themed employee-management app called "Vulnerable Startup," where the vulnerabilities get more realistic and more layered the further you go, starting with a login bypass and ending in a chained, second-order exploit that took me a while to actually understand, not just execute.

There's a "Show Query" toggle in the top right that shows the live SQL being run as you type, which made it easy to see exactly why a payload worked or didn't instead of guessing. I leaned on it constantly.

## Breaking the first login

First challenge, `profileID` is an integer field, so there's no string to escape out of:

```
1 or 1=1-- -
```

That was it. Every row came back true, and the app logged me in as whoever the query returned first.

The second challenge wraps the same field in quotes, so the payload needs a quote to close the string before the logic kicks in:

```
1' or '1'='1'-- -
```

One thing that tripped me up early and kept tripping me up for the rest of the room: a bare `--` doesn't reliably comment anything out in MySQL. It needs a trailing space (or any character) after the second dash to actually register as a comment. Without it, a stray quote from the original query template is left dangling and breaks the whole thing. Switching to `-- -` fixed it every time this came up, so I started defaulting to it without thinking.

**Flags:** `THM{dccea429d73d4a6b4f117ac64724f460}`, `THM{356e9de6016b9ac34e02df99a5f755ba}`

## Getting past client-side validation

The next two challenges added JavaScript that restricts input to letters and numbers. This is where it became obvious that client-side validation isn't a security control at all, it's just a UX nicety the attacker never has to interact with.

For the GET-based form, I skipped the JS entirely by just typing the payload straight into the URL:

```
http://<ip>:5000/sesqli3/login?profileID=-1' or 1=1-- -&password=a
```

The browser URL-encodes it automatically and the request never touches the form's JS at all.

The POST-based version needed a different approach since there's no URL to edit. I intercepted the request in Burp Suite and changed the `profileID` field directly in the raw body before forwarding it. Same comment-syntax issue from before showed up again here too, a bare `--` left a stray quote behind and broke the query until I added the trailing space back in.

Once the login succeeded I had a session cookie, and sending that forward with Burp Repeater to the home page pulled the flag straight out of the rendered HTML.

**Flags:** `THM{645eab5d34f81981f5705de54e8a9c36}`, `THM{727334fd0f0ea1b836a8d443f09dc8eb}`

## Turning an UPDATE into a read, then a write

This one was my favorite part of the room. The target is a profile edit form that updates a nickname and an email. Injecting into one field only (`asd',nickName='test',email='hacked`) updated both columns, which told me the underlying query was something like:

```sql
UPDATE <table> SET nickName='name', email='email' WHERE <condition>
```

The trick here is that `UPDATE` statements don't normally give you anything back to read, but if the field you're writing into gets displayed back to you afterward, you've effectively turned a write into a read channel. I fingerprinted the database with `sqlite_version()` (SQLite 3.31.1), then used `sqlite_master`, SQLite's version of `information_schema`, to enumerate every table:

```sql
',nickName=(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'),email='
```

That surfaced two tables, `usertable` and `secrets`, the second one wasn't in the room's own walkthrough, so lab instances must seed slightly different data. I pulled the full `usertable` schema the same way, then dumped every row with `group_concat()`. Six users total, with Admin sitting at ID 99 while everyone else was 10 through 14, a pretty common real-world pattern meant to avoid collisions with auto-incrementing user IDs.

I ran one of the dumped password hashes through a hash identifier (SHA-256), cracked it with an online tool, and got `toor` back, which matched the login password I'd already used to get in. That confirmed the crack was good. From there I generated a fresh SHA-256 hash in CyberChef and wrote it straight into Admin's password field through the same injection point. Logged in as Admin, found the flag in the `secrets` table.

Going from reading data out of a write-only operation to actually overwriting another account's password is a meaningfully bigger deal than a read-only SQLi finding. If I were on the defending side, I'd want any `UPDATE`/`INSERT` endpoint to get the same log scrutiny as a `SELECT`-heavy one. An oddly long or structured value landing in a field that should hold a short nickname is a solid anomaly to alert on.

**Flag:** `THM{b3a540515dbd9847c29cffa1bef1edfb}`

## Dumping everything with UNION

The second track opens with the same login bypass, confirming the pattern carries over into a different codebase, then moves into a challenge asking me to dump every password without touching blind injection.

I confirmed the login query selects two columns by incrementing `NULL` placeholders until the login succeeded:

```
1' UNION SELECT NULL-- -
1' UNION SELECT NULL, NULL-- -
```

With the column count known, I swapped in a real extraction query:

```sql
' UNION SELECT 1,group_concat(password) FROM users-- -
```

The dumped passwords showed up both on the page and inside the Flask session cookie, which I decoded separately with a session decoder just to see it for myself. Worth remembering that query output can end up living somewhere you didn't expect once it gets passed into a session.

UNION-based injection is loud. The response visibly changes in a specific, predictable way, which makes it fast to exploit but also the easiest category to catch from a monitoring standpoint.

**Flags:** `THM{f35f47dcd9d596f0d3860d14cd4c68ec}`, `THM{fb381dfee71ef9c31b93625ad540c9fa}`

## Going blind

This challenge removed every visible signal. No page content difference, no useful session data, just a login that either works or doesn't. That meant boolean-based blind injection, pulling the admin password one character at a time using `SUBSTR()`.

The app lowercases input before it reaches the query, so comparing a guessed character directly (`= 'T'`) never matches. I worked around that by supplying the character as its hex value cast to text, which sidesteps the lowercasing entirely:

```sql
admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1) = CAST(X'54' as Text)-- -
```

I found the password length first the same way, then tried the provided exploit script to see the mechanics in action before reaching for proper tooling. It loops through every position and every possible character, converting each guess to hex and checking whether the response contains "Invalid." Slow, but it made the logic click in a way reading the theory alone didn't.

For the real automation I used sqlmap, though the room's documented command didn't reliably find the injection point on its own:

```bash
sqlmap -u "http://<ip>:5000/challenge3/login" \
  --data="username=admin&password=admin" \
  --level=5 --risk=3 --dbms=sqlite --technique=B \
  -p username --not-string="Invalid" --dump
```

Explicitly targeting `-p username` and giving sqlmap a clear true/false string to key off of was what actually got it working. Even then it was slow going, with multiple connection timeouts along the way, which tracks since boolean-based blind means a full request cycle per character. Eventually it finished and handed me the flag.

Blind injection being slow is exactly what makes it detectable. A long run of near-identical requests hitting the same login endpoint, each one differing by a character or two, is a volume pattern that's often easier to spot in logs than trying to parse payload content directly.

**Flag:** `THM{f1f4e0757a09a0b87eeb2f33bca6a5cb}`

## The notes page that remembered too much

This is where the room stopped being about finding the vulnerable field and started being about understanding why a "safe" query can still get you burned.

The login is patched here, and the new feature is a Notes page. The query that inserts a note is correctly parameterized, the query structure is locked in first and user input is bound in afterward as pure data, so it genuinely cannot be reinterpreted as SQL. That part really is safe.

The catch is the query that reads notes back concatenates the stored username directly:

```sql
SELECT title, note FROM notes WHERE username = '" + username + "'
```

So a malicious value that was safely stored at registration becomes a live injection the moment that account's own Notes page loads. The exploit doesn't fire at write time, it fires later, on a completely different, unrelated read. I registered a sequence of usernames to walk this through step by step: first `' union select 1,2'` just to confirm I had control over both displayed columns, then one that enumerated every table via `sqlite_master`, and finally one that dumped the password table:

```sql
' union select 1,group_concat(password) from users'
```

Logged in as that last account, opened Notes, found the flag sitting right there.

I also worked through, without running it live, how this would need to be automated with sqlmap. Since the injection point (registration) and the vulnerable read (the Notes page) are two separate requests, a standard sqlmap run can't connect them. It needs a custom tamper script that registers an account, logs in, and injects the resulting session cookie into the next request so sqlmap can chain all three steps per payload attempt.

This is the clearest example in the whole room of why "we use parameterized queries" isn't a complete answer on its own. It has to hold for every query that ever touches that piece of data, not just the one that first received it.

**Flag:** `THM{4644c7e157fd5498e7e4026c89650814}`

## Trusting data that was never safe to trust

Next challenge: the Notes bug is fixed, and now it's a Change Password feature that's vulnerable instead. The new password value is parameterized correctly, but the username used in the `WHERE` clause comes from the session rather than from the form, and the developer apparently treated that as inherently safe:

```sql
UPDATE users SET password = ? WHERE username = '" + username + "'
```

Except that username had originally been set by the user at registration, so it was attacker-controlled the whole time, just several steps removed from the request that actually exploits it. I registered an account named `admin'-- -`, logged in as it, and changed its own password. The resulting query becomes:

```sql
UPDATE users SET password = ? WHERE username = 'admin'-- -'
```

The comment strips the rest of the original condition, so the update lands on the real admin account instead. Logged back in as admin with the new password and grabbed the flag.

The useful lesson here isn't really about the SQL, it's that where a value currently lives (session, database, request body) says nothing about whether it was ever attacker-influenced somewhere upstream. "It's not raw user input" and "it's safe" are two different claims.

**Flag:** `THM{cd5c4f197d708fda06979f13d8081013}`

## Chaining two vulnerable queries together

The last two challenges center on a book search feature. The first version concatenates the search term straight into a `LIKE` clause:

```sql
SELECT * from books WHERE id = (SELECT id FROM books WHERE title like '" + title + "%')
```

Closing the string and the wildcard with `') or 1=1-- -` dumped every book, confirming the vulnerability, and from there a UNION matched to the query's four columns pulled the password table straight out.

The harder version of this challenge splits the same idea into two separate queries. One fetches a book's ID based on the search term, a second then uses that ID in a query of its own:

```python
bid = db.sql_query(f"SELECT id FROM books WHERE title like '{title}%'", one=True)
if bid:
    query = f"SELECT * FROM books WHERE id = '{bid['id']}'"
```

Both queries are independently injectable. I could have gone after this blind, but since the second query is also vulnerable, it was simpler to chain a UNION through both instead. I built the payload in stages: force the first query to return nothing real, confirm I controlled what fed into the second query's `WHERE id =`, then escape into the second query's own string literal by doubling the quote so I could run a UNION inside it too:

```sql
' union select '-1''union select 1,2,group_concat(password),4 from users-- -
```

That returned the password dump straight in the search results.

No single request in this chain looks obviously malicious by itself, it's the sequence across two requests that actually matters. That's a decent argument for correlating logs across a session instead of judging each request in isolation.

**Flags:** `THM{27f8f7ce3c05ca8d6553bc5948a89210}`, `THM{183526c1843c09809695a9979a672f09}`

## What I learned

Every single vulnerability in this room traces back to the same root cause: user input landing directly in a query string instead of being treated as data. The specific shape changed every time, a login form, an UPDATE, a search field, a stored value read back later, but the underlying mistake never did.

The bigger thing I took away is that "parameterized" isn't a property of an app, it's a property of a specific query. A query can be written perfectly safely and still sit inside a system that's exploitable, because a different query downstream reads the same data without the same care. That gap between where a payload gets planted and where it actually goes off is the part of SQL injection I'd underestimated before this room, and it's exactly the kind of thing worth having in mind going into a defensive role meant to catch it.

**Why string concatenation in SQL queries is the root cause:** every vulnerability in this lab traced back to the same mistake: user input dropped directly into a query string instead of being treated as pure data. The specific syntax varied (login forms, UPDATE statements, search fields), but the underlying flaw never did.

**Why parameterized doesn't mean "safe" app-wide:** a query can be perfectly parameterized and still be part of a vulnerable system. If a different, unsafe query later reads the data that safe query stored. Safety is a property of every query touching a piece of data, not of the one that first receives it.

**Why blind injection is slow but not weak:** without any visible output, extracting data one character at a time via true/false responses (or response timing) is tedious by hand, but it's just as complete as reading data directly off the page, and it's exactly what tools like sqlmap exist to automate.

## Skills Practiced

- SQL injection: classic, UNION-based, boolean-based blind, UPDATE-statement, second-order/stored
- Client-side control bypass via direct URL manipulation and Burp Suite request interception
- Database schema enumeration via SQLite's `sqlite_master` table
- Hash identification and cracking (SHA-256)
- Session cookie analysis and decoding (Flask sessions)
- Automated exploitation and custom tamper script development with sqlmap

## Tools

- **Burp Suite** - intercepting and modifying POST requests to bypass client-side validation
- **sqlmap** - automated boolean-based blind injection and second-order injection via a custom tamper script
- **CyberChef** - generating a SHA-256 hash for the credential overwrite
- **Flask session decoder** - inspecting session cookie contents for leaked query data
- **SQLite** - target database engine throughout the room

Detailed notes and walkthrough with full screenshots [here](https://github.com/angeline-infosec/notes/blob/main/Web/SQL-Injection-Lab.md).



