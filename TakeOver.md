# [TakeOver](https://tryhackme.com/room/takeover) – Offensive Recon Lab

 Platform: ![TryHackMe](https://img.shields.io/badge/TryHackMe-1abc9c?style=flat-square) | Difficulty: Beginner–Intermediate | Perspective: Attacker


## Lab Overview

This lab simulated an external reconnaissance engagement against the futurevera.thm environment. The objective was to enumerate the target domain, discover hidden subdomains, and identify misconfigurations that expose sensitive content- the same initial steps a real attacker would take before attempting deeper access.

Rather than relying on brute-force or exploitation, the lab demonstrated how passive techniques like certificate inspection and virtual host analysis can reveal infrastructure that was never meant to be public.

## What I Learned

### Why subdomain enumeration matters:

Modern web applications are rarely a single domain. Companies run separate subdomains for support portals, admin panels, staging environments, and internal tools. Each of these is a potential attack surface. Attackers enumerate subdomains to map the full scope of a target's exposure before deciding where to push further.

### Why TLS certificates leak information:

When a certificate is issued for multiple domains, those domains are listed in the Subject Alternative Names (SAN) field. This is a standard feature but it means any subdomain covered by a wildcard or multi-domain certificate may be visible to anyone who inspects the certificate. Administrators frequently forget this when provisioning certs for internal or semi-private systems.

### Why HTTP and HTTPS can behave like different applications:

HTTPS enforcement, redirects, and virtual host routing can all be configured independently. An endpoint that appears safe over HTTPS may be completely unprotected over HTTP if the server configuration was not consistent. Testing both protocols is a basic but often missed step in web enumeration.

## Investigation Steps

### Step 1 — Environment Setup & Connectivity | ⚙️ Prerequisite

What happened:

My Initial nmap scans returned inconsistent results. Hosts appeared down and ports appeared filtered despite the target being online. Some digging and I realised the TryHackMe VPN interface (tun0) was not properly active. Without routing traffic through the VPN tunnel, packets never reached the target network. 

Why this matters:

Recon tools are entirely dependent on stable routing. A silent connectivity failure can produce misleading results like filtered ports, unreachable hosts, etc., that look like findings rather than tool errors. Confirming VPN connectivity (ip a, checking tun0 is up) is a mandatory first step before any scan.

### Step 2 — Subdomain Discovery | 🔍 Reconnaissance

What happened:

After scanning to check which ports are open on the target domain futurevera.thm, we discovered a web server running on ports 80 and 443, plus SSH on port 22.

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/428269dd-d330-46f7-a3f2-b1663acfdbd5" />


After accessing the main site at futurevera.thm, contextual clues in the lab suggested a support system existed. The subdomain support.futurevera.thm was then added to /etc/hosts  using the following command:

                                     sudo nano /etc/hosts

And inside it was added, 
                       
                      [machineIP]   futurevera.thm   support.futurevera.thm

   <img width="761" height="51" alt="image" src="https://github.com/user-attachments/assets/e31bbc6f-0306-4633-858a-a99e2096b9d8" />


and successfully resolved to a live support portal.

Why this matters:

In a real engagement, this step would involve tools like ffuf, gobuster, or passive sources like certificate transparency logs. The /etc/hosts modification simulates the DNS resolution a real attacker would achieve after discovering the subdomain. It makes the target accessible through the browser without a public DNS entry.

### Step 3 — TLS Certificate Inspection | 🔐 Key Finding

What happened:

Now, visiting support.futurevera.thm in the browser gives us a warning certificate

 <img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/8db806d9-f50a-4b94-9b10-84e0dacc581c" />


While inspecting the HTTPS certificate for support.futurevera.thm, the Subject Alternative Names field revealed an additional subdomain that was not discoverable through conventional enumeration:

                                     secrethelpdesk934752.support.futurevera.thm

 <img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/7a49d323-6f08-4048-83b0-9862e6989699" />
                                    

Now, we map it in our /etc/hosts file like before using the  "sudo nano /etc/hosts" command.

    Added like:  [machineIP]   futurevera.thm   support.futurevera.thm   secrethelpdesk934752.support.futurevera.thm

<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/5c449988-74f7-4f0f-be5c-d9eb1f62724e" />
    


Why this is significant:

Certificates issued for internal or semi-private systems often include hostnames that were never intended to be public. Because TLS certificates are publicly logged through Certificate Transparency (CT) logs, anyone can query services like crt.sh to enumerate all subdomains covered by a target's certificates, no active scanning required. This subdomain would have been invisible to a wordlist-based brute-force but was fully exposed through the certificate itself.

### Step 4 — HTTP vs HTTPS Behavior Analysis | 🌍 Critical Difference

What happened:

Accessing the newly discovered subdomain over HTTPS returned a normal, unremarkable page with no useful content.

                             https://secrethelpdesk934752.support.futurevera.thm
                    
Switching to plain HTTP revealed completely different behavior - the server redirected to an AWS S3-style static page that was not access-controlled.

                             http://secrethelpdesk934752.support.futurevera.thm


Why this is significant:

The server's HTTPS and HTTP configurations were inconsistent. HTTPS was likely routed through a reverse proxy or load balancer with proper controls applied. HTTP bypassed those controls entirely and hit backend infrastructure directly, in this case, an S3-hosted static site with no authentication. This is a misconfiguration, not an exploit. The attacker did nothing unusual; the server handed over the content voluntarily.

### Step 5 — Flag Retrieval | 🎯 Objective Complete


<img width="940" height="488" alt="image" src="https://github.com/user-attachments/assets/b16dc1ae-686a-4261-bf6a-1c82375b836e" />


The exposed HTTP endpoint served accessible content including the lab flag, confirming that the misconfigured virtual host allowed unauthenticated access to content that should have been protected.

                              flag{beea0d6edfcee06a59b83fb50ae81b2f}


## Key Takeaways

* **Connectivity must be verified before recon begins**. Silent routing failures produce misleading scan output. Confirming tun0 is active and pinging the target before running tools saves significant time.
* **Certificates are a recon goldmine**. SAN fields expose hostnames regardless of whether they are indexed, linked, or discoverable through DNS. Querying Certificate Transparency logs via crt.sh should be a standard early step in any external recon engagement.
* **Protocol consistency is a security control**. Assuming HTTPS protection applies equally to HTTP is a common misconfiguration. Always test both - they can be routed to entirely different backends.
* **Misconfigurations cause more breaches than exploits**. No vulnerability was exploited here. The exposed content was the direct result of inconsistent server configuration. This is representative of real-world findings in bug bounties and penetration tests.
  

## Skills Practiced

* External reconnaissance and subdomain enumeration
* TLS certificate analysis and SAN field inspection
* Virtual host discovery and /etc/hosts manipulation
* HTTP vs HTTPS behavioral analysis
* Cloud storage misconfiguration identification
  

## Tools & Technologies

* nmap - Port scanning and service enumeration
* Browser certificate inspector - TLS/SAN field analysis
* crt.sh / Certificate Transparency logs - Passive subdomain discovery
* /etc/hosts – Local DNS resolution for virtual host testing


### Conclusion

The TakeOver room illustrated how far a disciplined attacker can get without touching a single exploit. Certificate inspection, protocol switching, and virtual host enumeration, all passive or low-noise techniques, were sufficient to discover and access content the target organisation likely believed was hidden.

The lab reinforces a core principle in offensive security: attack surface exposure is often self-inflicted through misconfiguration, and the most productive recon technique is simply looking carefully at what the target is already telling you.

