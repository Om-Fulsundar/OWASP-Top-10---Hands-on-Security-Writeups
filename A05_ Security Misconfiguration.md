# OWASP Top 10 Labs Series #5 — A05: Security Misconfiguration

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. This is entry #5. Follow along for A01 through A10.

---

## The Bug — What Is A05 Security Misconfiguration?

One line: someone left a default setting on that should have been turned off, or put a sensitive file somewhere public and never locked it down. No fancy exploit needed. Just knowing where to look.

OWASP keeps it in the top five because it's everywhere and it's easy. An attacker doesn't need a zero-day. They need a browser and patience.

That's exactly what this lab was. I poked at a boring file, followed a trail of small misconfigs, and ended up reading a document marked "This is confidential. Do not distribute." Zero credentials. Just a URL.

---

## Recon — Where I Started

I always start with `robots.txt`. Web admins add sensitive paths there to hide them from search engines, which from an attacker's perspective is just a public list of interesting directories.

Fired a `GET /robots.txt` through Burp Suite and checked the HTTP history.

**[SS1 — Burp HTTP History: GET /robots.txt → 200 OK, response shows "Disallow: /ftp"]**

<img width="1727" height="777" alt="Screenshot 2026-06-14 152246" src="https://github.com/user-attachments/assets/3311ea76-4383-4f36-97a3-26687678d5c8" />


Response had two lines that mattered: `User-agent: *` and `Disallow: /ftp`. The app just told me exactly where to go next.

---

## Finding 1: Open Directory at /ftp — Everything Just Sitting There

Navigated directly to `http://localhost:3000/ftp`.

**[SS2 — Browser showing /ftp directory listing with acquisitions.md, package.json.bak, incident-support.kdbx, encrypt.pyc, suspicious_errors.yml visible]**

<img width="1918" height="707" alt="Screenshot 2026-06-14 152349" src="https://github.com/user-attachments/assets/346882b0-2a47-4d79-8c17-1ef3042c44f9" />


No auth prompt. Full directory listing. A few names immediately stood out:

- `acquisitions.md` — business acquisition plans sitting in a public folder
- `incident-support.kdbx` — a KeePass password database
- `package.json.bak` — dev backup file, useful for stack fingerprinting

Directory listing enabled on a public route is a misconfiguration at the server level. Express ships with `serve-index` and nobody turned it off.

---

## Finding 2: Confidential Business Doc — Zero Auth Required

Clicked `acquisitions.md`.

**[SS3 — Browser showing /ftp/acquisitions.md: "# Planned Acquisitions" — "This document is confidential! Do not distribute!" — mentions competitor acquisitions and stock market impact]**

<img width="938" height="633" alt="Screenshot 2026-06-14 152604" src="https://github.com/user-attachments/assets/d1cf4ad1-23c9-4ea5-a299-69674ac00c90" />


Right at the top: *"This document is confidential! Do not distribute!"*

The person who wrote that warning knew it was sensitive. Someone just forgot to connect that to an access control. In a real company this is material non-public information. Insider trading territory. Accessible from a browser with no session, no token, nothing.

---

## Finding 3: 403 That Still Leaked Everything (The Sneaky One)

This is the one that looks minor and isn't. I tried accessing `package.json.bak`. Server blocked it with a 403.

**[SS4 — Browser showing /ftp/package.json.bak: 403 error page titled "OWASP Juice Shop (Express ^4.22.1)" with full Windows filesystem stack trace including build/routes/fileServer.js:59:18]**


<img width="1918" height="693" alt="Screenshot 2026-06-14 152836" src="https://github.com/user-attachments/assets/47e35fdc-12c8-4f65-813c-daa3e68b4b76" />


The error page title: **"OWASP Juice Shop (Express ^4.22.1)"** — framework version, right there. Below that, a full stack trace with:

- Absolute Windows file paths on the host machine
- Internal source file names and line numbers (`build/routes/fileServer.js:59:18`)
- Full Node module structure

Access was denied. But the response handed me the tech stack, the internal directory layout, and exactly which file enforces the filter. If Express ^4.22.1 has a CVE, I now know exactly what to search. This is how a blocked request still helps an attacker. In real reports this gets marked "Low." It shouldn't.

---

## Finding 4: Path Traversal — Tested, Blocked

Tried escalating from the open `/ftp` directory using Burp Repeater.

**[SS5 — Burp Repeater: GET /ftp/../../../../etc/passwd → 403 Forbidden, security headers visible in response]**

<img width="1462" height="722" alt="Screenshot 2026-06-14 153535" src="https://github.com/user-attachments/assets/1623b5cc-6b22-4682-9424-723685175959" />


Standard payload: `/ftp/../../../../etc/passwd` → 403
URL-encoded: `/ftp/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` → 403

Both blocked. Traversal protections are working. Documenting this because a real assessment covers what you tested, not just what broke.

---

## The Full Attack Chain

`robots.txt` → reveals `/ftp` → open directory listing → read `acquisitions.md` (confidential data) → try `package.json.bak` → blocked but error leaks framework version + internal file paths → look up CVEs for Express ^4.22.1 → targeted exploitation.

No exploit written. No credentials needed. Just reading what the app volunteered.

---

## What I Didn't Test But Exists

This is where A05 gets broader than just directory listing. Security Misconfiguration covers a whole family of bugs and I only scratched the surface in this lab. Here's what else lives under this category and what I'd go after next.

**Cracking the KeePass Database**

`incident-support.kdbx` is sitting right there in the `/ftp` directory. KeePass databases are encrypted but not uncrackable. Download the file, run it through `hashcat` with the KeePass module (`-m 13400`) and a decent wordlist like `rockyou.txt`. Weak master passwords crack fast. If that database has credentials for internal systems, one misconfigured public folder just became a full account takeover vector.

**Decompiling the Python Bytecode**

`encrypt.pyc` is compiled Python. Run it through `uncompyle6` or `pycdc` and you get readable source back. Developers sometimes compile scripts thinking it obscures the logic. It doesn't. Hardcoded API keys, encryption keys, internal endpoints — anything the developer put in that script is now readable to anyone who downloaded it from the open `/ftp` directory.

**Default Credentials**

A massive chunk of A05 in the real world is default credentials that nobody changed. Admin panels shipped with `admin:admin`, `admin:password`, or vendor-specific defaults. Tools like `changeme` or just checking CIRT.net for the device/software defaults are standard recon steps. Juice Shop itself has an admin account exploitable through other challenges. In production, default creds on routers, Jenkins instances, database UIs like phpMyAdmin, and cloud management consoles are responsible for a huge number of breaches.

**Cloud Storage Misconfigurations**

S3 buckets and Azure Blob containers set to public read are one of the most common real-world A05 findings right now. There are tools like `S3Scanner` and `GrayhatWarfare` that actively hunt misconfigured buckets. The attack is almost identical to what I did here — find a publicly accessible storage endpoint, browse what's in it, download anything sensitive. The only difference is scale. A misconfigured S3 bucket in production can expose millions of records instead of one markdown file.

**Exposed Admin Panels and Debug Interfaces**

Applications sometimes leave debug routes, admin panels, or framework dashboards exposed without authentication. Django's debug mode, Laravel's Telescope, Spring Boot Actuator endpoints, phpMyAdmin — all of these have been found publicly accessible on production servers. Actuator endpoints alone can expose heap dumps, environment variables with secrets, and live application metrics. One unauthenticated `/actuator/env` hit in the wrong app and you're reading database passwords out of the response.

**Missing or Misconfigured Security Headers**

The Juice Shop responses showed `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN` which is good. But plenty of apps ship without `Content-Security-Policy`, without `Strict-Transport-Security`, or with CORS set to `Access-Control-Allow-Origin: *` on authenticated endpoints. A wildcard CORS header on an API that reads user data means any malicious website can make credentialed requests to that API on behalf of a logged-in user. That's a misconfiguration that directly enables cross-origin data theft.

**Unnecessary Features and Services Left Enabled**

Sample applications, test endpoints, old API versions, unused services running on non-standard ports — all of this falls under A05. Developers spin up a test route, forget about it, and it ships to production. Or a server has FTP enabled from a setup two years ago and nobody disabled it. Attack surface grows silently through features nobody is actively using or monitoring.

---

## Real Breaches This Maps To

**Capital One, 2019** — misconfigured WAF let an attacker pull AWS metadata credentials. 100 million records. Root cause: config error, not code.

**Dow Jones, 2017** — S3 bucket set to public read. Subscriber data exposed. Same pattern as the `/ftp` listing, different cloud service.

**Cit0day, 2020** — misconfigured Elasticsearch left open to the internet. 5 billion records. Someone never changed a default.

**Twitch, 2021** — source code, internal tooling, and creator payout data leaked. Misconfigured internal access controls on a Git repository.

---

## Remediation

| Issue | Fix |
|---|---|
| Directory listing on `/ftp` | Remove `serve-index` middleware or gate it behind authentication |
| `robots.txt` leaking internal paths | Remove sensitive paths from it entirely; use `X-Robots-Tag: noindex` response headers instead |
| Verbose error messages | Set `app.set('env', 'production')` in Express; log full traces server-side only, return generic errors to client |
| Sensitive files in web-accessible paths | Move off the web server entirely — KDBx files, backups, and compiled scripts don't belong on a public route |
| Default credentials | Enforce credential rotation on first deploy; automate checks in your CI pipeline |
| Cloud storage | Audit bucket/container permissions on every deploy; enable public access blocks by default |

---

## Three Takeaways

`robots.txt` is not a security control. Listing a path there is advertising it, not hiding it.

A 403 isn't always a win. The status code was right but the error response leaked the entire stack. The right HTTP status means nothing if the body is doing the attacker's recon for them.

Misconfigs chain. No single mistake here was catastrophic alone. `robots.txt` plus open directory plus no access control plus verbose errors — together that's a complete recon package handed over for free. That's why A05 is dangerous. It's never one thing. It's five small decisions that nobody connected.

---

> **Lab:** OWASP Juice Shop (local, localhost:3000) | **Tools:** Burp Suite Community, Browser DevTools | **Category:** OWASP A05:2021 — Security Misconfiguration
>
> *Part of my OWASP Top 10 Labs Series — documenting all ten categories hands-on. More writeups coming.*
