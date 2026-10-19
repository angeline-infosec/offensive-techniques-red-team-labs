# [Lost Fortune](https://tryhackme.com/room/thm-ctf-jackpot-overflow) - TryHackMe

**Room:** Lost Fortune **Category:** Web **Difficulty:** Easy **Points:** 60 **Tags:** Web, OWASP, Black Box, Burp Suite

## Briefing

> The house always keeps a back room, and this one never quite closed its doors. Somewhere behind the neon and the noise sits a forgotten terminal, still quietly serving up files to anyone who knows how to ask nicely.
> 
> Word on the floor is the old system trusts its visitors a little too much. Find the door, learn its language, and see what the dealer never meant to hand over.

## A quick detour: APT vs. LFI

Before diving in, it's worth being precise about terminology. I initially conflated two completely different classification axes here, so I'm documenting the distinction for my own future reference as much as anyone else's.

**Advanced Persistent Threat (APT)** describes a *threat actor* — typically a well-resourced, often nation-state-affiliated group running long-term, stealthy campaigns against a target. It's a classification of *who* is attacking and *how* they operate (patience, stealth, specific objectives like espionage or sabotage), not a vulnerability or technique in itself.

**Local File Inclusion (LFI)** is a *vulnerability class* — a web application flaw where user-supplied input is used, insufficiently validated, to construct a filesystem path that the server then reads and returns. It's a subtype of **Path Traversal / Directory Traversal**, classified under **OWASP A01:2021 – Broken Access Control** and **CWE-22**.

The two sit on entirely different axes. One describes an attacker's sophistication and persistence. The other describes a specific class of coding flaw. An APT group might *use* an LFI vulnerability as part of a campaign, but the terms aren't interchangeable.

## Recon

Connected to the VPN and loaded the target in browser.

`[ SCREENSHOT: initial kiosk landing page ]`

The kiosk — "Secret Village Archive Terminal" — presents two documents and states its request format plainly:

```
Request format: ?doc=<filename>
Only .pdf and .png documents are served from this terminal.
```

This is a strong signal: a parameter directly referencing a filename, served by the backend. Worth testing as a potential Local File Inclusion / path traversal vector before anything else.

Baseline test — requesting the legitimate document to confirm expected behavior:

```
http://10.48.153.61/?doc=village_schedule.pdf
```

`[ SCREENSHOT: village_schedule.pdf rendering correctly ]`

Confirmed — the PDF rendered normally. Also pulled `important.png` out of curiosity:

`[ SCREENSHOT: important.png — Hackerman meme ]`

Just a meme (Mr. Robot "Hackerman" reaction image) — likely flavor/red herring rather than a clue, noted but not pursued further unless something later points back to it.

## Testing for path traversal

Attempted a basic traversal against the baseline:

```
http://10.48.153.61/?doc=../../../../etc/passwd
```

`[ SCREENSHOT: result of basic traversal attempt ]`

This came back as a clean 403, with the message "Only .pdf and .png village documents may be viewed." So plain traversal characters were not being blocked outright. The request was reaching the application and getting rejected on something else, likely the extension check hinted at in the kiosk's footer text.

## Narrowing down the filter

To figure out what the filter was actually checking, I ran a few diagnostic tests rather than guessing blindly:

- `?doc=important.png.txt` downloaded a blank file instead of getting rejected with the pdf/png message. This told me the filter does a substring check (does `.pdf` or `.png` appear anywhere in the string) rather than a true suffix check (does the string end with `.pdf` or `.png`).
- `?doc=nonexistent.pdf` returned a blank PDF viewer page rather than the rejection message, confirming the same thing from a different angle, and giving me a baseline for what "passed the filter but file doesn't exist" looks like.
- A null byte attempt (`%00.png`) came back as a 500 Internal Server Error with an empty body. Checked in Burp Repeater to confirm this wasn't a browser encoding issue. This ruled out null byte truncation, which only worked on PHP versions before 5.3.4 anyway.
- A literal `#.png` suffix triggered a 400 Bad Request from Apache itself, since `#` is a reserved URL character I hadn't encoded. Not meaningful filter data, just a malformed request.
- A literal `?.png` suffix came back 200 OK with `Content-Disposition: filename="passwd?.png"`. The server tried to open a file literally named that, which doesn't exist, so the body was empty. Confirmed this wasn't a working bypass either, just another "passed the filter, file doesn't exist" case.

`[ SCREENSHOT: Burp Repeater showing the 500 response for the null byte attempt ]`

## Getting the source

Ran gobuster against the root to see what else was exposed:

```
gobuster dir -u http://10.48.153.61 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php
```

Only `index.php` and `server-status` (403) came back. That told me the entire application logic lived in one file, which made reading its source the highest value next step.

Since the filter only checks for the substring `.pdf` or `.png` anywhere in the input, and PHP has stream wrappers like `php://filter` that let you reference a resource without using a normal file path at all, I tried combining the two:

```
curl http://10.48.153.61/?doc=php://filter/convert.base64-encode/resource=index.php | base64 -d
```

This worked and returned the full PHP source.

`[ SCREENSHOT: decoded index.php source ]`

## Exploitation

The source made the actual bug clear. The filter logic looked like this:

```php
$is_wrapper = (strpos($doc, '://') !== false);

if (!$is_wrapper) {
    if (stripos($doc, '.pdf') === false && stripos($doc, '.png') === false) {
        http_response_code(403);
        die('Only .pdf and .png village documents may be viewed.');
    }
    $path = (isset($doc[0]) && $doc[0] === '/') ? $doc : $base . $doc;
} else {
    $path = $doc;
}
```

The extension whitelist only runs when the input does not contain `://`. The moment it does, the app skips the whitelist entirely and skips restricting the path to the `village_docs/` folder, and just hands the raw string straight to `readfile()`. This is not really a traversal bug at all in the end. It is a missing validation branch for an entire class of input (any PHP stream wrapper), discovered because the substring check for `.pdf`/`.png` happened to match on `php://filter/read=pdf/...` without the developer realizing a stream wrapper URI could satisfy that same substring test.

With that confirmed, I went looking for the flag using the same technique, trying plausible paths:

```
curl http://10.48.153.61/?doc=php://filter/resource=/var/www/html/flag.txt
curl http://10.48.153.61/?doc=php://filter/resource=/var/www/html/village_docs/flag.txt
```

Both came back 200 OK with `Content-Length: 0`, meaning those exact paths did not exist. I confirmed the actual docroot by reading the Apache vhost config the same way:

```
curl http://10.48.153.61/?doc=php://filter/resource=/etc/apache2/sites-enabled/000-default.conf
```

This confirmed `DocumentRoot /var/www/html`, ruling out a wrong assumption about the path. The flag turned out to be sitting one directory above the docroot entirely:

```
curl http://10.48.153.61/?doc=php://filter/convert.base64-encode/resource=/var/www/flag.txt | base64 -d
```

`[ SCREENSHOT: terminal output showing the base64 blob and decoded flag ]`

## Flag

`THM{wr4pp3rs_sk1p_th3_wh1t3l1st}`

The flag text itself basically confirms the root cause: PHP stream wrappers skipped the whitelist entirely.

## What a defender would have seen

Flipping this to the blue team side for a moment, since this repo frames offensive work through a SOC lens too. The attack pattern here would be fairly loud in Apache access logs: a burst of requests to `?doc=` with repeated `../` sequences, then `%00`, then `php://filter/...` variants, all from one source IP in a short window. A few detection angles:

- A WAF rule or log alert on `php://`, `data://`, `expect://`, `zip://`, or any `://` substring inside a query parameter value would have caught this cold, since the app itself had no such check.
- Repeated 403 responses from the same IP against the same endpoint within a short time window is a classic brute-force/fuzzing signature, worth alerting on regardless of the specific payload.
- The underlying fix is straightforward: validate `$doc` against an allowlist of exact expected filenames (`village_schedule.pdf`, `important.png`) rather than trying to pattern-match safe input, and never pass user input directly into `readfile()` without first resolving and confirming the real path stays inside the intended directory (e.g. `realpath()` plus a prefix check).

## Takeaways

This room was a good reminder that an extension whitelist is only as strong as the code path that enforces it. The developer clearly thought "check for .pdf or .png anywhere in the string" was a reasonable filter, without accounting for the fact that PHP treats `://` as a completely different kind of input (a stream wrapper reference) rather than a plain filename, and that a wrapper URI can still contain the substring being checked for.

A few things I would do differently or carry forward:

- I spent a while guessing plausible flag filenames and paths one at a time (`flag.txt` in several directories) before stepping back and reading the actual source code and config files. Pulling the source early, once I realized `php://filter` worked at all, would have saved time versus guessing blind.
- A "file exists but is empty" response and a "file genuinely does not exist" response can look identical from the outside (both come back as empty bodies). Checking full headers (status code, `Content-Length`) rather than just the rendered page in browser made it much easier to tell these apart.
- The actual sensitive file was placed just outside the web root (`/var/www/flag.txt`, not inside `/var/www/html/`), which is a common CTF pattern worth trying early rather than only searching inside the docroot.
