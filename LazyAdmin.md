# [LazyAdmin](https://tryhackme.com/room/lazyadmin) – Web Exploitation & Privilege Escalation Lab
Platform: ![TryHackMe](https://img.shields.io/badge/TryHackMe-1abc9c?style=flat-square) | Difficulty: Easy | Perspective: Attacker

<img width="940" height="262" alt="image" src="https://github.com/user-attachments/assets/ee0232f9-1192-43c6-a80e-ce56a6b8acae" />


## Lab Overview

This lab simulated a full end-to-end offensive engagement against a Linux web server running a poorly maintained CMS (Content Management System is the software application used to build, manage, and update websites). The objective was to enumerate exposed services, discover sensitive resources, compromise administrative credentials, achieve remote code execution, and escalate to root, all through misconfigurations and weak security practices rather than complex exploits.

LazyAdmin is a realistic representation of what attackers find when they target organisations that deploy third-party web applications without hardening them. Every step of the chainfrom exposed backups to sudo abuse, reflects vulnerability classes that appear regularly in real-world penetration tests and bug bounty reports.

## What I Learned

### Why web directory enumeration is essential:

A web server's publicly accessible surface is rarely just its homepage. Hidden directories may contain administrative portals, backup files, configuration data, or CMS components that were never intended to be exposed. Brute-forcing common directory names is a standard and productive early step in any web engagement.

### Why backup files are a critical exposure risk:

Developers and administrators routinely create database backups for disaster recovery. When these are stored in web-accessible directories without access controls, they become a goldmine for attackers. A single SQL backup can contain usernames, password hashes, and the entire structure of the application's data which is enough to completely compromise authentication.

### Why file upload functionality is dangerous:

CMS platforms that allow authenticated users to upload files can become a direct path to remote code execution if the upload validation is weak. An attacker who can upload a PHP file to a web-accessible directory has effectively gained the ability to run arbitrary commands on the server.

### Why sudo misconfigurations lead to full compromise:

Linux privilege escalation frequently comes down to one question: what can the current user run with elevated permissions? When sudo is granted over a script that the attacker can modify, or that calls another writable file, root access is trivial. The escalation here required no exploit, only careful enumeration and one file write.


## Investigation Steps

### Step 1 — Service Enumeration | ⚙️ Reconnaissance

What happened:

The engagement began with an nmap scan to identify exposed services on the target.

           nmap -sCV 10.48.157.202 

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/c6a3dc1f-0aab-44c7-b486-dcfad03cce31" />


Looking at the scan, we can see both ports 80 and 22 are open. 
Port 80 running an HTTP web server, and port 22 running SSH
SSH was noted as a potential secondary access path if credentials were later recovered, but the web server was the obvious initial attack surface.

Why this matters:

Understanding what services are exposed determines where reconnaissance effort is focused. A web server on port 80 immediately implies directory enumeration, CMS identification, and application-layer attack paths. SSH on port 22 implies that any credentials discovered during web enumeration might also grant direct shell access.


### Step 2 — Web Directory Enumeration | 🔍 Initial Discovery

What happened: 

Directory brute-forcing was run against the root of the web server using a common wordlist. 

        gobuster dir -u http://10.48.157.202/ -w /usr/share/wordlists/dirb/common.txt

        
<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/3e8f821c-2e3f-4fa1-b7e8-0ceeda8d5018" />


<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/43548777-9cbc-449a-9a44-530e82a32a0b" />



This returned a /content directory as the primary interesting finding. Visiting it in the browser immediately identified the running application as SweetRice CMS, displayed through its default welcome message.

Why this matters:

Identifying the CMS is a significant intelligence gain. Known CMS platforms have documented administrative paths, known vulnerabilities, default configurations, and common backup structures. Once SweetRice was identified, the next logical step was to enumerate deeper into its directory structure with that context in mind.


### Step 3 — CMS Directory Enumeration | 🔍 Deeper Enumeration

What happened:

A second gobuster scan was run specifically against the /content path, which returned several directories. 

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/f1716ab8-436d-44da-a33d-1f3e45d0e03d" />


<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/6bd7ad47-44d2-4180-a3d9-623f6e903641" />


Two were immediately notable:

/as — the SweetRice administrative login panel

/inc — internal application resources, including a subdirectory called mysql_backup

Why this matters:

CMS platforms follow predictable directory conventions. Enumerating recursively, rather than stopping at the first interesting result, consistently uncovers more of the attack surface. The admin panel at /as confirmed that authentication could be targeted. The /inc directory opened the door to something far more serious.

### Step 4 — SQL Backup Discovery & Credential Extraction | 🗄️ Key Finding

What happened:

Inside /content/inc/mysql_backup/, a publicly accessible SQL backup file was available for direct download: 
          
             mysql_bakup_20191129023059-1.5.1.sql

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/53a7ae38-99e0-4974-b5b0-50f5d14aa6ca" />
             

The file was downloaded and inspected locally. Within the backup, an administrator account entry was visible, including a username and a password hash:

             Username: manager
             Hash: 42f749ade7f9e195bf475f37a44cafcb

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/a661d0a3-2025-410e-b817-8ab8998ee2d6" />
             

The hash was identified as MD5 and cracked using an online cracking tool, returning the plaintext password Password123.


<img width="940" height="360" alt="image" src="https://github.com/user-attachments/assets/e4ada20a-37f2-40a7-a020-dbff6ce508d7" />


Why this is significant:

This is one of the most impactful misconfiguration patterns in web application security. The backup was stored in a web-accessible path with no authentication, no access controls, and no download restrictions. The password was hashed using MD5, an algorithm considered cryptographically broken for password storage, and the password itself was trivially weak. This single file handed over complete administrative access to the application.
In a real engagement, this would represent a critical finding: unauthenticated access to database credentials with no rate limiting, alerting, or protection of any kind.


### Step 5 — Administrative Access | 🔓 Authentication Compromise

What happened:

The recovered credentials were used to authenticate to the SweetRice admin panel at /content/as. Login was successful on the first attempt.

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/e5a46a3e-f453-4852-bc86-aeb757721712" />


Why this matters:

Authenticated access to a CMS admin panel dramatically expands the attack surface. Features that were previously inaccessible-file uploads, editing, and plugin management are now available. Any one of these can be a path to code execution if not properly secured.


### Step 6 — Reverse Shell Upload & Remote Code Execution | 💻 Initial Access

What happened:

A PHP reverse shell payload was downloaded, configured with the attacker's IP and listening port, and renamed with a .php5 extension to bypass file type restrictions in the upload interface.

            wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/f6175e0d-80e2-480f-8769-e651d9d8d85a" />

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/2e8c9efa-f68a-40cb-b4c7-30d03ca7700f" />



The payload was uploaded through the SweetRice Media Center. A Netcat listener was started on the attacker's machine:

             nc -lvnp 4444

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/9636c282-82af-4eab-999e-4e17a1e1ef6d" />
             

Navigating to the uploaded file's URL triggered execution, and a reverse shell connected back running as www-data, the web server's service account.

The shell was then stabilised:

             python3 -c 'import pty; pty.spawn("/bin/bash")'
             

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/6a30eb01-6ebb-4bc5-a08d-c00beae60a72" />


Why this matters:

The upload filter was checking file extensions but not validating that the file content was actually a permitted media type. Renaming a PHP file to .php5 was enough to bypass it, the PHP interpreter still executed the file. This is a well-known weakness in extension-only validation. The correct control is to validate MIME type, reject executable extensions comprehensively, and store uploads outside the web root entirely.


### Step 7 — Post-Exploitation Enumeration | 🗂️ Internal Discovery

What happened:
   
With shell access established, enumeration of the /home directory revealed a user account named itguy. Their home directory contained three files of interest: a Perl script (backup.pl), a MySQL credential file (mysql_login.txt), and the user flag.

              cat user.txt
              → THM{63e5bce9271952aad1113b6f1ac28a07}

 <img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/9e87c331-0ba1-445f-b7ff-c5417609e70a" />              
 

Why this matters:

Post-exploitation enumeration is not just about finding flags; it is about understanding the environment. User home directories frequently contain credentials, configuration files, and scripts that reveal both the system's purpose and its weaknesses. The Perl script here turned out to be the key to privilege escalation.
              

### Step 8 — Privilege Escalation via Sudo Misconfiguration | ⬆️ Root Access

What happened:

Running sudo -l revealed that the www-data account had permission to execute a specific Perl script with root privileges and without a password:

              (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl

Inspecting backup.pl showed it did nothing except call another script:

              system("sh", "/etc/copy.sh");

Checking /etc/copy.sh confirmed it was world-writable. The contents were replaced with a command to spawn a root shell:

              echo "/bin/bash -i" > /etc/copy.sh
  
Running the privileged Perl script via sudo then executed the modified shell script with root permissions:

             sudo /usr/bin/perl /home/itguy/backup.pl
             → root@THM-Chal

             cat /root/root.txt
             → THM{6637f41d0177b6f37cb20d775124699f}

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/57d6ecc3-af40-4e0e-bf5b-72207bf03480" />


             
<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/85b4f87f-a2c6-499b-aae4-6586daa07343" />


Why this is significant:

This escalation path is a textbook example of indirect sudo abuse. The sudo rule technically restricted execution to a specific script, but that script called a second file that had no access controls. Granting elevated execution over any script that references external, writable paths is equivalent to granting root directly.
The attacker required no exploit, no kernel vulnerability, and no password. One file write was enough.


## Attack Chain Summary 

Nmap scan → Web server identified
→ Gobuster → /content (SweetRice CMS)
→ Gobuster on /content → /as (admin panel), /inc (backup directory)
→ SQL backup downloaded → credentials extracted
→ MD5 hash cracked → admin password recovered
→ Admin panel authenticated
→ PHP reverse shell uploaded via Media Center
→ Shell triggered → www-data access
→ Home directory enumeration → backup.pl discovered
→ sudo -l → NOPASSWD perl execution identified
→ /etc/copy.sh found writable
→ copy.sh overwritten → root shell obtained


## Key Takeaways

* **Enumerate recursively, not just shallowly**. The most critical finding in this lab is the SQL backup. It was not at the root of the web server. It required a second enumeration pass against a subdirectory. Stopping after the first scan would have missed it entirely.
  
* **Backup files in web directories are a critical exposure**. SQL backups contain credentials, schema, and configuration data. Storing them anywhere within the web root, without authentication, is equivalent to publishing them. Backup storage should be off-server or behind strict access controls.
  
* **Extension-only upload validation is not sufficient**. Renaming a PHP reverse shell to .php5 bypassed the filter entirely. Robust upload handling requires content inspection, restricted execution environments, and storage outside the web root.
  
* **Sudo scope must include all referenced files**. A sudo rule is only as restrictive as the full execution path it permits. If a privileged script calls a writable file, the restriction is meaningless. Least privilege means auditing not just what is allowed, but what those permitted actions subsequently invoke.
  
* **Weak password hashing accelerates credential compromise**. MD5 was never designed for password storage. Its speed is a liability. Billions of hashes can be computed per second. Modern applications must use bcrypt, scrypt, or Argon2. Weak hashing combined with a weak password produced a compromise that took seconds.


## Skills Practiced

* Network reconnaissance and service enumeration
* Web directory brute-forcing and CMS identification
* Backup file discovery and credential extraction
* MD5 hash identification and cracking
* Authenticated file upload abuse
* PHP reverse shell deployment and stabilisation
* Linux post-exploitation enumeration
* Sudo misconfiguration identification and abuse
* Writable script exploitation for privilege escalation


## Tools & Technologies

* nmap — Port scanning and service enumeration
* Gobuster — Web directory brute-forcing
* Netcat — Reverse shell listener
* PHP reverse shell (pentestmonkey) — Remote code execution payload
* Linux CLI utilities — Post-exploitation enumeration and file manipulation


### A Note on MITRE ATT&CK

MITRE ATT&CK is a framework that categorises the techniques attackers use across the stages of an intrusion. Each technique has an ID and a name.
For example, the sudo abuse in this lab maps to **T1548.003: Abuse Elevation Control Mechanism — Sudo and Sudo Caching**. Defensive teams use this framework to align their detections and controls to known attacker behaviour. ATT&CK will become a regular reference point for both threat hunting and incident analysis.


## Conclusion 

LazyAdmin demonstrated that a full system compromise from unauthenticated external access to root can be achieved entirely through misconfiguration and weak security hygiene. No sophisticated exploits were required at any stage. An exposed backup handed over credentials. Weak upload validation handed over code execution. A writable script handed over root.

This is consistent with how real-world compromises unfold. Attackers follow the path of least resistance, and in this environment, that path was marked clearly at every step. The lab reinforces that defensive effort is most effective when focused on hardening configuration, enforcing access controls, and auditing privilege grants, rather than solely on patching known CVEs.













