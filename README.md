# OWASP Top 10 Labs Series

A hands-on exploitation and documentation project covering all ten OWASP Top 10 (2021) vulnerability categories. Each writeup is based on real lab work using OWASP Juice Shop (TryHackMe) and PortSwigger Web Security Academy, documented with actual screenshots, payloads, and attack chains.

Built as a practical portfolio piece - not theory, not walkthroughs, but first-person exploitation with attacker mindset at each step.

---

## The Series

| # | Category | Platform | Key Bugs |
|---|---|---|---|
| A01 | Broken Access Control | Juice Shop | IDOR on basket API, forced browsing to admin panel, hidden route discovery via JS bundle |
| A02 | Cryptographic Failures | Juice Shop | MD5 password hashing, JWT alg:none bypass, credentials over plain HTTP |
| A03 | Injection | Juice Shop | SQL injection login bypass, UNION-based data extraction, hash cracking, HTML injection |
| A04 | Insecure Design | Juice Shop + PortSwigger | Negative quantity manipulation, client-side price tampering |
| A05 | Security Misconfiguration | Juice Shop | robots.txt recon, open directory listing, confidential document exposure, verbose error disclosure |
| A06 | Vulnerable and Outdated Components | Juice Shop | Null-byte bypass to extract package.json.bak, CVE mapping via NVD, Retire.js scan on jQuery 2.2.4 |
| A07 | Identification and Authentication Failures | PortSwigger | OAuth implicit flow bypass, redirect_uri hijacking for account takeover |
| A08 | Software and Data Integrity Failures | PortSwigger | JWT RS256→HS256 algorithm confusion, alg:none signature stripping |
| A09 | Security Logging and Monitoring Failures | PortSwigger | Coupon limit overrun via parallel requests, rate limit bypass via Turbo Intruder race attack |
| A10 | Server-Side Request Forgery | PortSwigger | Basic SSRF to internal admin panel, blacklist bypass via double URL encoding |

---

## Tools Used

Burp Suite Professional, Burp JWT Editor, Burp Turbo Intruder, OWASP Juice Shop, Browser DevTools, NVD, CrackStation, Retire.js, jwt.io

---

## About

I'm a final-year B.Tech Computer Science student pursuing cyber security roles. This series documents my hands-on OWASP Top 10 lab work as part of building a practical security portfolio.

Connect with me on [Medium](https://medium.com/%40om.fulsundar.7370) | [GitHub](https://github.com/Om-Fulsundar) | [TryHackMe](https://tryhackme.com/p/gr0ot)
