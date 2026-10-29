# PHP2Shell - TryHackMe
 Platform: ![TryHackMe](https://img.shields.io/badge/TryHackMe-1abc9c?style=flat-square) | Perspective: Attacker

**Category:** Web / PHP Runtime (not application-layer)

**Vulnerability class:** Dangling pointer from an improperly-handled OOM bailout (CWE-824: Access of Uninitialized Pointer), split into a memory-disclosure flaw and an RCE flaw - CVE-2026-109618 and CVE-2026-109619, both CVSS v4.0 9.2 Critical

## Scenario
On 21 October 2026 the PHP project disclosed two critical vulnerabilities, together nicknamed PHP2Shell, that let an unauthenticated attacker run commands on almost any PHP server using nothing but ordinary HTTP requests. No login, no file upload the application has to accept, and no bug in the application code itself: the flaw sits in the PHP runtime, underneath whatever framework or CMS happens to be installed. The vulnerable code had existed since PHP 5.4.0 in 2012, so the disclosure reached fourteen years of releases at once. The goal across this room was to understand the harmless feature the bug abuses, see the exact engine mistake that turns it into a weapon, run the public exploit chain against a vulnerable server, and pull a flag as the web server user.

## In Plain English
Strip away the CVE numbers and this is a four-step story:

1. **PHP has a progress-bar feature.** When you upload a file, PHP can track how far along it is, so a page can show a progress bar. To use it, the upload form just needs a field called `PHP_SESSION_UPLOAD_PROGRESS`. This tracking code runs the instant PHP starts reading the upload, before the website's own code has done anything at all, so no login is needed to reach it.
2. **PHP has a "panic exit" for running out of memory.** If a request uses too much memory, PHP can't keep going, so it jumps straight out, skipping its usual tidy-up. Normally tidy-up means: free the memory, then forget the address that pointed to it. The panic exit skips the "forget the address" step.
3. **That leftover address becomes a problem because workers get reused.** The same Apache worker process handles request after request. So that forgotten address doesn't disappear with the failed request, it's still sitting there when the next request comes in, and now that next request can decide what gets put at that address.
4. **Attackers do this twice, for two different payoffs.** First, they make the server reveal its own memory layout by reading that leftover address back out through the session cookie (CVE-2026-109618), undoing a defense called ASLR that's supposed to keep memory addresses secret. Then, now that they know exactly where things live, they get the same leftover address to point at a fake object whose "cleanup instructions" are actually the command `system()`. When PHP goes to clean it up, it unknowingly runs the attacker's command instead (CVE-2026-109619).

The reason this is scary isn't the mechanism, it's that steps 1 through 4 never touch the application. The lab's entire "app" is one line that prints `OK`, and the exploit works against it anyway.

## Task 1: Connecting to the Lab
Started the target machine and connected over SSH as instructed:

```bash
ssh ubuntu@10.48.152.215
```

The server runs a vulnerable PHP install behind Apache in a container on `127.0.0.1:8088`, and the exploit tooling is already present in the `ubuntu` user's home directory. No questions to answer here, this task is setup.

![screenshot: SSH session connected to the attackbox](screenshot-task1-ssh.png)

## Task 2: A Harmless Feature - Upload Progress
This task was theory covering `session.upload_progress`, PHP's built-in way of reporting file-upload progress back to a page. When a form includes a field named `PHP_SESSION_UPLOAD_PROGRESS` (the default name the setting looks for), PHP writes live progress data into the session while it is still reading the multipart request body off the wire. That happens during body parsing, which is one of the very first things PHP does, well before the request environment is initialized and well before the target script runs a single line. That timing is the whole foothold: no `session_start()`, no login, and no application logic at all is required to reach this code. Any URL on the server that accepts a POST request is enough.

**Q: What is the default name of the form field that switches on PHP's upload-progress tracking?**
**A:** `PHP_SESSION_UPLOAD_PROGRESS`

## Task 3: The Bug - A Bailout at the Wrong Moment
Also theory. PHP caps memory per request with `memory_limit`. When a request exceeds it, PHP cannot continue normally, so it performs a bailout: a `longjmp()` straight back to a safe recovery point, skipping the orderly cleanup a request normally does (free memory, then clear the pointer to it). If the out-of-memory hit lands between those two steps, in that gap after a block is freed but before the pointer to it is cleared, the bailout leaves a dangling pointer behind. On its own that's harmless since the request is dead, but Apache's prefork `mod_php` setup reuses the same worker process across requests, so the stale pointer survives into whatever lands on that worker next. Whoever controls what gets allocated into that freed space controls what the pointer now resolves to. One root cause, two CVEs: 109618 is the memory-disclosure path, 109619 is the code-execution path.

**Q: What one-word name does the PHP engine give to the longjmp it performs to abort a request that hits a fatal error such as running out of memory?**
**A:** `bailout`

**Q: What is the CWE identifier for the weakness class behind PHP2Shell? (format: CWE-NNN)**
**A:** `CWE-824`

## Task 4: Reconnaissance - Confirming the Target
Confirmed the container and PHP version:

```bash
$ docker ps --format '{{.Names}}  {{.Image}}  {{.Status}}'
php2shell-target  php:8.4.26-apache  Up 33 minutes

$ docker exec php2shell-target php -v
PHP 8.4.26 (cli) (built: Oct 21 2026 00:31:19) (NTS)
```

![screenshot: docker ps and php -v output](screenshot-task4-recon.png)

8.4.26 is one release behind the 8.4.27 fix, confirming the target is vulnerable. Checked what was actually being attacked:

```bash
$ curl -s http://127.0.0.1:8088/index.php
OK

$ docker exec php2shell-target cat /var/www/html/index.php
<?php echo "OK\n"; ?>
```

![screenshot: curl output and index.php source](screenshot-task4-index.png)

The entire application is a single echo statement. No login form, no upload feature, no database, nothing to find at the application layer. That's the point of the room: if the attack lands against this page, it lands against the runtime, not the app, and a real WordPress or Laravel site is no better protected just because its own code is clean.

Listed the exploit tooling already on the box:

```bash
$ ls ~/php2shell-bypass-aslr-exp
ASLR_PATHS.md  NOTES_BG.md  logs  ASLR_PURE_HTTP.md  NO_DISPLAY_ERRORS.md  out
ASLR_PURE_HTTP_RESEARCH.md  README.md  readme_en.md  DISPLAY_ERRORS_OFF.md  docker  src
HTTP_HEAP_LEAK.md  e.py  tools  NOASLR_REPORT.md  exploit.py  NOTES.md  lab
```

![screenshot: exploit directory listing](screenshot-task4-exploit-dir.png)

**Q: What version of PHP is the target server running?**
**A:** `8.4.26`

**Q: What single word does the target page at /index.php print in response?**
**A:** `OK`

## Task 5: Leaking Memory and Defeating ASLR (CVE-2026-109618)
ASLR randomizes where code and data load specifically so an attacker can't predict addresses. This CVE removes that protection by reading the dangling pointer back as a string. An out-of-memory condition is provoked while a session ID is being handled, leaving a stale pointer to it; a follow-up request reoccupies that freed space so the pointer now describes a string with an attacker-inflated length. When PHP sends the session cookie, it reads out that oversized string and hands it back in the `Set-Cookie: PHPSESSID` header, up to roughly 67 KB of the worker's actual memory per request. Ran the exploit to watch the leak stage:

```bash
$ cd ~/php2shell-bypass-aslr-exp
$ python3 exploit.py -u http://127.0.0.1:8088/index.php
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x70d1a2c00000
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x70d1a4911000
```

![screenshot: exploit.py output showing the heap and libphp leak](screenshot-task5-leak.png)

Two leaks: the heap base and the libphp (PHP engine library) base, both pulled straight out of `Set-Cookie` headers. Addresses differ every run since ASLR is still doing its job, the exploit just reads them fresh instead of guessing.

**Q: Which HTTP response header does CVE-2026-109618 abuse to return leaked process memory to the attacker?**
**A:** `Set-Cookie`

## Task 6: From a Leak to a Shell (CVE-2026-109619)
With the heap and library locations known, this CVE reoccupies the dangling reference again, this time with a forged internal `HashTable` structure whose destructor pointer (`pDestructor`) is set to the now-known address of `system()`. When PHP tidies up that value at the end of request handling, it calls what it believes is a routine destructor and instead calls `system()` with attacker-controlled bytes as the argument. Ran the full chain:

```bash
$ python3 exploit.py -u http://127.0.0.1:8088/index.php
[*] stage 3: HTDATA=0x7170436690d8 ZIF=0x7170457d4370
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

![screenshot: exploit.py proving code execution as www-data](screenshot-task6-rce.png)

Confirmed RCE as `www-data` from nothing but multipart POST requests, in under ten seconds, against a page with no application bug. Retrieved the flag:

```bash
$ python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'cat /f>/out/p1' --proof-file out/p1
PROOF: THM{b4ilout_l3aves_th3_h3ap_dang1ing}
```

![screenshot: flag retrieved](screenshot-task6-flag.png)

**Q: When the exploit runs, which system user do the commands execute as?**
**A:** `www-data`

**Q: What is the flag returned by the exploit?**
**A:** `THM{b4ilout_l3aves_th3_h3ap_dang1ing}`

## Task 7: Detection, Mitigation and the Real Fix
The only complete fix is patching the PHP runtime (8.5.12, 8.4.27, 8.3.36, or 8.2.35) and restarting every worker, since updating the application framework on top does nothing, the vulnerable code is below it. Interim measures: `session.upload_progress.enabled = 0` plus a worker restart removes the trigger for most reported techniques, `opcache.enable = 0` frustrates the execution path, `fatal_error_backtraces = 0` addresses 109619 specifically on PHP 8.5, and blocking `multipart/form-data` at the edge stops delivery at the cost of breaking legitimate uploads. A PHP-module WAF does not help here, since it only inspects traffic once control passes to the application, and this attack finishes before that point.

**Q: Which PHP 8.4 release fixes PHP2Shell?**
**A:** `8.4.27`

**Q: Which php.ini directive, set to 0, disables the feature the attack relies on for delivery?**
**A:** `session.upload_progress.enabled`

## Why This Worked
This is a single root-cause bug exposed as two CVEs. The feature that provides the foothold, `session.upload_progress`, runs during request body parsing, which is before any application code executes, so pre-authentication reach was built into the feature by design, nobody saw that as an attack surface because it was never meant to be reachable with malicious intent. The actual flaw is a timing gap in PHP's own bailout handling: an out-of-memory `longjmp()` skips the pointer-clearing step of normal cleanup, so a block gets freed but the pointer to it doesn't get reset. Combined with Apache's prefork model reusing worker processes across requests, that stale pointer isn't scoped to the dead request, it persists and gets reused by whatever the attacker sends next. CVE-2026-109618 reads it to leak memory and beat ASLR; CVE-2026-109619 overwrites it with a forged destructor to get code execution. Neither CVE needs the C library or any gadget outside PHP's own code, the whole chain is built from the engine.

## How I'd Fix It
Patch the PHP runtime to 8.5.12/8.4.27/8.3.36/8.2.35 and restart every worker, this is the only fix that actually closes the bug, everything else is a stopgap. Until patched, disable `session.upload_progress` and restart workers to remove the delivery trigger, and run PHP workers with least privilege so a successful chain has the smallest possible blast radius. Don't rely on a PHP-module WAF as a compensating control for this class of bug specifically, since the damage completes before the application (and anything hooked into it) ever runs; protection needs to sit in the patched runtime itself or at a layer in front of PHP, like an edge proxy rejecting multipart bodies carrying `PHP_SESSION_UPLOAD_PROGRESS`. Build detection around oversized `PHPSESSID` values in `Set-Cookie` headers and PHP worker OOM crashes correlated with multipart traffic, both are observable before a vendor signature exists.

## What I Learned
This was my first runtime-level bug worked end to end rather than an application-layer one, and the part that stuck with me is how little the application mattered, `index.php` is a single echo and the exploit doesn't care. It reframed how I think about "patch the app" as a control: necessary, but it has a ceiling, and that ceiling is the runtime underneath it. The leak-then-corrupt pattern (read memory to beat a mitigation, then write to hijack control flow) is also a shape worth recognizing outside PHP specifically, it's the same two-step a lot of memory-safety exploits in compiled languages follow, just told here inside an interpreter instead of raw C.

## Interview Prep: PHP2Shell
This is the section to reread before a SOC interview, pitched at "what would I actually be asked."

**Q: What is PHP2Shell, in one or two sentences?**

A: A pair of critical PHP runtime bugs (not application bugs), disclosed October 2026. A legitimate upload-progress feature runs code before the application does; if PHP hits an out-of-memory bailout at the wrong instant during that code, it leaves a dangling pointer instead of cleaning up properly. One CVE uses that to leak server memory and defeat ASLR, the other overwrites it with a forged object to get `system()` called with an attacker's command, giving unauthenticated RCE against basically any PHP app.

**Q: Why doesn't patching the application fix this?**

A: Because the vulnerable code isn't in the application, it's in the PHP engine's own memory-bailout handling. A WordPress or Laravel site with zero bugs of its own is exactly as exposed as the room's one-line test page, since the flaw sits below the framework layer entirely. The only real fix is patching the PHP runtime (the interpreter package or the base container image) and restarting every worker so none of them keep the old code resident.

**Q: What could a SOC have done before a patch or vendor signature existed?**

A: Alert on oversized `PHPSESSID` values in `Set-Cookie` headers, PHP's session IDs are a known fixed length, so anything larger is anomalous by definition rather than something needing a tuned threshold. Alert on PHP worker crashes or OOM errors correlated with multipart POST traffic, especially any spike right after the public disclosure. Watch for `PHP_SESSION_UPLOAD_PROGRESS` appearing in POST bodies to endpoints with no legitimate upload feature. Push the interim mitigation (disable upload progress, restart workers) immediately while the real patch gets scheduled, and get an accurate inventory of which hosts run which PHP version, since this affected PHP 5.4 through 8.5.x, asset accuracy mattered more than usual here.

**Q: What should a SOC do once it suspects exploitation happened?**

A: Treat any hit on the detection signals above as potential pre-auth RCE rather than a crash to shrug off, the memory-disclosure path alone can leak secrets (session data, API keys, even TLS private keys) even before an attacker goes for code execution. Don't assume a WAF caught it, this attack completes before the application layer a WAF inspects is even reached. If a worker crash correlates with execution indicators, unexpected child processes under `www-data`, outbound connections from a PHP worker, assume compromise, rotate session secrets and API keys, and check patch level across every PHP-serving host, not just the one that alerted.

**Q: Why can't an in-process WAF stop this?**

A: Timing. A WAF running as a PHP module only gets to inspect a request once PHP hands control to the application. This entire attack, body parsing, the bailout, the dangling-pointer reuse, completes before the application, and anything hooked into it, ever runs. There's nothing for an in-process filter to see. Protection has to live in the patched runtime itself or at a layer genuinely in front of PHP.

**Things to know cold, not just recognize:**
- The bug class: CWE-824, access of an uninitialized/dangling pointer, caused by a `longjmp()` bailout that skips cleanup.
- Why the feature runs pre-auth and pre-application: it fires during multipart body parsing, before the request environment initializes and before the script runs.
- The split between the two CVEs: 109618 is disclosure (oversized string leaked via `Set-Cookie`), 109619 is execution (forged `pDestructor` pointed at `system()`).
- Why a prefork/mod_php worker model makes this exploitable across requests: the dangling pointer survives because the worker process isn't recycled between requests.
- Why an in-process WAF can't stop it: the exploit's damage is done before the application layer the WAF inspects even runs.
