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






