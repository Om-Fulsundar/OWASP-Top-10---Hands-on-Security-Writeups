# OWASP Top 10 Labs Series #2 - A02: Cryptographic Failures

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. This is entry #2. Follow along for A01 through A10.

---

## The Bug - What Is A02 Cryptographic Failures?

A02 covers situations where cryptography is either absent, misimplemented, or too weak to provide real security. It's not just about encryption - it includes how passwords are stored, how tokens are signed and verified, and whether sensitive data travels over protected channels.

Three bugs in this lab, each hitting a different layer of the same problem. Weak hashing on passwords at rest, broken signature verification on JWTs in transit, and no TLS anywhere. Any one of these would be a critical finding on its own. Together they mean an attacker can recover credentials, forge authentication tokens, and intercept everything in plaintext - without ever touching a sophisticated exploit.

---

## Bug 1 - Weak Password Hashing: MD5 With No Salt

### Extracting the Hashes

Used the UNION SELECT injection on the search endpoint from the A03 lab - same vulnerability, different angle this time. Instead of just demonstrating SQL injection, the extracted data is the point.

**[SS1 - Burp Repeater: UNION SELECT id,email,password FROM Users query in the search parameter, response showing all user records with emails and MD5 hashes - admin@juice-sh.op with hash 0192023a7bbd73250516f069df18b500 visible alongside jim@juice-sh.op, bender@juice-sh.op, bjoern.kimminich@gmail.com and others]**
<img width="1841" height="660" alt="Screenshot 2026-07-09 151738" src="https://github.com/user-attachments/assets/86f6a707-a131-4ead-a733-cfef0294a944" />



The full Users table - emails and password hashes for every account - returned in a single query. The hash format is immediately recognizable as MD5: 32 hex characters, no prefix, no salt indicator anywhere in the stored value.

MD5 was never designed for password storage. It's a general-purpose hashing algorithm built for speed, which is exactly the opposite of what password hashing requires. A modern GPU can compute billions of MD5 hashes per second.

### Cracking the Admin Hash

Copied the admin hash: `0192023a7bbd73250516f069df18b500`. Pasted into CrackStation.

**[SS2 - CrackStation: hash 0192023a7bbd73250516f069df18b500 identified as MD5, result column shows "admin123" highlighted in green - exact match]**
<img width="1332" height="402" alt="Screenshot 2026-07-09 151842" src="https://github.com/user-attachments/assets/8015d9c3-7c9e-4473-9743-a40f13087e9a" />



Cracked instantly. No brute force needed - CrackStation matched it against a precomputed rainbow table. The hash was in the database. MD5 without salting means identical passwords produce identical hashes, so once one instance of `admin123` is cracked anywhere, every MD5 hash of `admin123` everywhere is cracked.

### Using the Recovered Password

Logged in with `admin@juice-sh.op` and `admin123`.

**[SS3 - Browser: Juice Shop showing challenge solved banner "Password Strength - Log in with the administrator's user credentials without previously changing them or applying SQL Injection", Account dropdown showing admin@juice-sh.op as the active user]**
<img width="1918" height="833" alt="Screenshot 2026-07-11 011519" src="https://github.com/user-attachments/assets/808687aa-071d-4a8f-aeb8-c3458d55df7a" />



Full admin access. The challenge flag confirms this - the application itself validates that the admin password was recovered from the hash and used to authenticate. Weak password hashing converted a read-only SQL injection finding into a complete account takeover.

---

## Bug 2 - JWT Signature Bypass: alg:none Attack

### Why This Is A02, Not A01

This is important to distinguish correctly. The JWT `alg:none` attack is a **cryptographic failure**, not a broken access control issue. JWTs derive their security entirely from the signature - the cryptographic proof that the token hasn't been tampered with. When the server accepts a token with no signature at all, it's not making a bad authorization decision. It's failing to perform cryptographic verification in the first place. The authentication mechanism itself is broken at the implementation level.

### Capturing the Authenticated Request

Logged in, captured a request that required authentication - `PUT /rest/products/24/reviews` to post a product review. The JWT was visible in the Authorization header.

**[SS4 - Burp Repeater: PUT /rest/products/24/reviews with Authorization Bearer JWT in the header, "JSON Web Token" tab visible in Burp, response showing HTTP 201 Created with status:success - this is the original valid signed request]**
<img width="1413" height="667" alt="Screenshot 2026-07-11 015147" src="https://github.com/user-attachments/assets/74eff8f8-70fb-4ef1-873f-894dbf867138" />



The request worked with a valid signed token. Now the question: what happens if the signature is removed entirely?

### Modifying the JWT to alg:none

Opened the JSON Web Token tab in Burp Repeater. The JWT Editor extension shows the decoded token - header, payload, and signature. Used the Attack function to apply the `None` algorithm attack.

**[SS5 - Burp JWT Editor: JSON Web Token tab showing the modified JWT, Header section displaying "typ": "JWT", "alg": "None", Payload showing iat: 1783712697, Signature section showing raw bytes, Information panel showing "Issued At - Sat Jul 11 2026 01:14:57 GMT+5:30"]**
<img width="806" height="731" alt="Screenshot 2026-07-11 015204" src="https://github.com/user-attachments/assets/ac5d22c2-9c05-4f93-8ab1-de78187a53d6" />



The header now reads `"alg": "None"`. The signature is stripped. The token is structurally a valid JWT - it has a header and payload - but carries no cryptographic proof of authenticity. Any claims in the payload could have been modified by anyone.

### Server Accepts the Unsigned Token

Sent the modified request.

**[SS6 - Burp JWT Editor with response panel: alg:None header visible, response shows HTTP 201 Created, status:success - server accepted the unsigned token]**
<img width="1423" height="675" alt="Screenshot 2026-07-11 015228" src="https://github.com/user-attachments/assets/71b089d2-38e0-44b2-bf81-2f00d384b11d" />




`201 Created`. The server processed the request and returned success. It never verified the signature because the algorithm field told it not to. The JWT library accepted `alg:none` as a valid instruction rather than rejecting it as an invalid or disallowed algorithm.

This means anyone can craft a JWT with any payload - change the email, change the role, change any claim - strip the signature, set `alg:none`, and the server will trust it. Token integrity is completely broken.

### Forged Review Challenge Solved

**[SS7 - Browser: Juice Shop challenge solved banner "Forged Review - Post a product review as another user or edit any user's existing review", Account dropdown showing admin@juice-sh.op]**
<img width="1918" height="936" alt="Screenshot 2026-07-11 015243" src="https://github.com/user-attachments/assets/b21b3b70-7e38-438d-a641-021948dfea86" />



The challenge confirms the impact. A review was posted under another user's identity using a forged unsigned token. In a real application this extends to anything the JWT authorizes - account actions, admin functions, any operation gated behind token verification.

---

## Bug 3 - Sensitive Data Over Plain HTTP

### Credentials in the Clear

Enabled Burp Intercept and submitted the admin login with the recovered credentials.

**[SS8 - Burp Intercept: POST /rest/user/login over HTTP, request body showing "email":"admin@juice-sh.op", "password":"admin123" in plaintext, URL bar shows http://10.49.129.153/rest/user/login with no TLS]**
<img width="1351" height="806" alt="Screenshot 2026-07-11 015648" src="https://github.com/user-attachments/assets/ab87ec31-cb61-49d2-a4a1-5714f65b6a9c" />



The login request containing `admin@juice-sh.op` and `admin123` in plaintext, transmitted over HTTP. No TLS. Anyone on the same network - same Wi-Fi, same ISP segment, any positioned attacker - can read this directly.

### JWT Returned Over HTTP

**[SS9 - Burp HTTP History: POST /rest/user/login highlighted with 200 OK, response showing authentication object with full JWT token and umail:admin@juice-sh.op, all over HTTP - "JSON Web Token" annotation visible in the Notes column]**
<img width="1837" height="728" alt="Screenshot 2026-07-11 015714" src="https://github.com/user-attachments/assets/c5b31393-3038-4b3e-a21c-cf7fab70cab6" />



The server responded with the full JWT in the response body, also over HTTP. So now not only were the credentials sent in plaintext, but the session token that proves authentication is also captured in the same intercept. An attacker on the network gets both in one request-response pair.

### Full Traffic Confirmation

**[SS10 - Burp HTTP History: full request list showing all traffic to 10.49.129.153 over HTTP - POST /rest/user/login, GET /rest/products/search, PUT /rest/products/24/reviews all visible without TLS column checkmarks, green highlights showing JWT-bearing requests]**
<img width="1918" height="750" alt="Screenshot 2026-07-11 015842" src="https://github.com/user-attachments/assets/d76ed9b3-1c09-4a5a-b076-14f2b5bf7f39" />



The HTTP history shows the complete picture - login, search, review submission, all application traffic flowing over HTTP. No TLS anywhere. The entire session - from credential submission through JWT issuance through every subsequent authenticated request - is readable in plaintext by a network observer.

---

## The Full Attack Chain

UNION SELECT from A03 → dumps Users table with MD5 hashes → CrackStation cracks admin hash to `admin123` → login with recovered credentials → admin session established → capture authenticated JWT → JWT Editor applies `alg:none` attack → server accepts unsigned token → forge reviews as other users → entire credential and token exchange happening over HTTP → network attacker intercepts everything.

Three independent cryptographic failures. Each one is damaging alone. Together they form a complete credential-to-session-to-impersonation kill chain.

---

## What I Didn't Test But Exists

**JWT Secret Brute Force**

Before trying `alg:none`, a standard approach is attempting to crack the JWT signing secret. If the application uses HMAC (HS256) with a weak or default secret, tools like `hashcat` with the JWT mode (`-m 16500`) or `jwt_tool` can recover the secret from a valid signed token. A recovered secret allows forging any token with a valid signature - more stealthy than `alg:none` since the forged token passes signature verification.

**RS256 to HS256 Algorithm Confusion**

If the application uses RS256 (asymmetric) and the public key is obtainable, an attacker can switch the algorithm to HS256 and use the public key as the HMAC secret. The server verifies with the public key, the attacker signs with it, and the signature passes. This is a more sophisticated variant of the same category - the server's key material is being used against its own verification logic.

**Bcrypt, Argon2, and Proper KDFs**

MD5 is broken for password storage. The correct alternatives are purpose-built key derivation functions: bcrypt, scrypt, and Argon2. These are intentionally slow and include a per-user salt by default. The work factor is configurable so as hardware gets faster, the cost can be increased. A properly salted bcrypt hash of `admin123` cannot be cracked by a rainbow table - each hash is unique even for identical passwords.

**HSTS and Certificate Pinning**

TLS alone isn't enough if the application doesn't enforce it. Without HTTP Strict Transport Security (HSTS), a user who types the HTTP URL gets served HTTP first, which can be intercepted before any redirect to HTTPS happens. Certificate pinning goes further - it prevents TLS interception by man-in-the-middle attackers using their own certificates. Both are relevant follow-up checks once TLS is confirmed as missing.

---

## Real Breaches This Maps To

**LinkedIn, 2012** - 6.5 million SHA-1 hashed passwords (no salt) were stolen and cracked within hours of the breach being disclosed. A follow-up investigation in 2016 revealed the full breach was 117 million accounts. Unsalted hashing meant rainbow tables cracked the majority of the dumped hashes almost immediately.

**Adobe, 2013** - 153 million user records exposed, passwords stored with 3DES encryption rather than hashing, and no per-user salt. Encryption is reversible; hashing isn't supposed to be. The encryption key was eventually obtained, making all 153 million passwords recoverable.

**Auth0, 2020 (JWT alg:none)** - Multiple JWT libraries were found to accept `alg:none` tokens, leading to widespread patches across the Node.js ecosystem. The vulnerability had existed for years in production JWT libraries before being systematically addressed. Juice Shop's acceptance of `alg:none` reflects the historical state of real library implementations.

---

## Remediation

| Issue | Fix |
|---|---|
| MD5 password hashing | Replace with Argon2id, bcrypt, or scrypt; enforce minimum work factor; add per-user random salt |
| No salt on hashes | Salting must be enforced at the application level - same password, different users, different hashes |
| JWT accepts alg:none | Explicitly allowlist permitted algorithms server-side; reject any token whose `alg` header is not on the approved list; never trust the `alg` field from the token itself |
| JWT library default permissiveness | Pin the verification algorithm in code rather than reading it from the token header - `jwt.verify(token, secret, { algorithms: ['RS256'] })` |
| No TLS | Enforce HTTPS across all endpoints; redirect HTTP to HTTPS; add HSTS header with long max-age; ensure session tokens and credentials are never transmitted over plain HTTP |

---

## Three Takeaways

MD5 being broken for password storage has been public knowledge since the 1990s. It's not a new finding. Applications still ship with it because developers use whatever hashing the database or ORM makes easiest, without checking whether it's appropriate for credentials. Password hashing needs a purpose-built KDF, not a general-purpose hash.

The `alg:none` vulnerability is a case study in what happens when you trust user-supplied input to control security logic. The JWT standard technically allows `alg:none` - it was designed for scenarios where the signature is established out-of-band. Every application that processes JWTs needs to explicitly reject it. The library shouldn't decide; the application code should enforce the allowlist.

Missing TLS is the most impactful of the three because it undermines every other control. It doesn't matter how strong the password hash is if the plaintext password travels over the network unencrypted. It doesn't matter how well the JWT is signed if the token itself is readable in transit. Cryptographic protections at the application layer are rendered worthless if the transport layer isn't protected.

---

> **Lab:** OWASP Juice Shop (TryHackMe instance, 10.49.129.153) | **Tools:** Burp Suite Professional, Burp JWT Editor, CrackStation, jwt.io | **Category:** OWASP A02:2021 - Cryptographic Failures
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
