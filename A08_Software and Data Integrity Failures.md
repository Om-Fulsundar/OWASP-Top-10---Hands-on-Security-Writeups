# OWASP Top 10 Labs Series - A08: Software and Data Integrity Failures - Two Ways to Forge a JWT

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. JWT authentication failures fall under A08:2021 (Software and Data Integrity Failures). This entry covers two PortSwigger labs - each exploiting a different flaw in how the server verifies token integrity. Follow along for the full A01 through A10 series.

---

## The Bug - What Is A08 Software and Data Integrity Failures?

A08 covers situations where an application makes decisions based on data whose integrity it doesn't properly verify. For JWTs specifically: the entire security model depends on the server verifying the token's cryptographic signature before trusting the claims inside it. If that verification is skipped, bypassed, or implemented incorrectly, an attacker can put anything in the token payload and the server will act on it.

Two labs, two different failure modes. The first accepts a token signed with the wrong algorithm and an empty key. The second accepts a token with no signature at all. Same outcome either way - administrator impersonation, account deletion, lab solved.

---

## Lab 1 - JWT Authentication Bypass via Unverified Signature

**Platform:** PortSwigger Web Security Academy

### Capturing the JWT

Logged in as `wiener:peter` and watched Burp HTTP History for the authentication flow.

**[SS1 - Burp HTTP History: POST /login returning 302 Found, Set-Cookie header visible in response containing the full JWT session token, request #10 highlighted showing "1 JWTs, 0 JWEs" in the Cookies column]**
<img width="1867" height="750" alt="Screenshot 2026-07-11 175754" src="https://github.com/user-attachments/assets/0773f5ea-6e4c-4776-86cd-b66ea480916c" />



The login response issued a JWT in the `session` cookie. Burp's JWT annotation confirms it detected the token. Located the follow-up authenticated request.

**[SS2 - Burp HTTP History: GET /my-account?id=wiener returning 200 OK, "JWT authentication bypass via unverified signature" in the Title column, "1 JWTs, 0 JWEs" visible - JWT in Cookie header carrying the session]**
<img width="1857" height="606" alt="Screenshot 2026-07-11 175859" src="https://github.com/user-attachments/assets/7714a56f-5ab3-4a9b-840c-cd4be7f064b4" />



The `GET /my-account` request carries the JWT in the Cookie header. This is the request to send to Repeater and modify.

### Decoding the Original Token

Opened the JSON Web Token tab in Burp Repeater.

**[SS3 - Burp JWT Editor: original JWT decoded, Header showing "kid": "f740c8ae-c4cf-40cb-95ee-40bd70a17aa2" and "alg": "RS256", Payload showing "iss": "portswigger", "exp": 1783776380, "sub": "wiener", Signature bytes visible, Information showing Expiration Time]**

<img width="863" height="892" alt="Screenshot 2026-07-11 180111" src="https://github.com/user-attachments/assets/26ac8fde-afdb-47f0-803c-9d2b2ee363f4" />



The original token uses RS256 - asymmetric signing. The server holds the private key to sign, and verifies with the public key. Changing `sub` alone won't work because the signature would no longer match. The attack here targets the algorithm, not just the payload.

### Forging the Token - RS256 to HS256 with Empty Key

Changed `"alg": "RS256"` to `"alg": "HS256"` and `"sub": "wiener"` to `"sub": "administrator"`. Used Burp's Sign function with an empty key.

**[SS4 - Burp JWT Editor: modified JWT, Header showing "alg": "HS256" (changed from RS256), Payload showing "sub": "administrator" (changed from wiener), new Signature bytes, Serialized JWT field highlighted in blue showing the forged token]**

<img width="857" height="782" alt="Screenshot 2026-07-11 180501" src="https://github.com/user-attachments/assets/f6139134-1ca7-4533-b3e8-a560f99bbabb" />



The attack logic: if the server uses the RS256 public key as the HMAC secret when it sees HS256, it verifies the token with a key it considers trusted. An empty key bypasses this entirely if the server's verification is loose enough to accept it. The forged token is signed with an empty HMAC secret.

### Admin Panel Accessed with Forged Token

Sent `GET /admin` with the forged JWT.

**[SS5 - Burp Repeater: GET /admin with forged JWT in Cookie, response 200 OK, HTML response body showing "JWT authentication bypass via unverified signature" page title, admin panel HTML returned]**
<img width="1863" height="677" alt="Screenshot 2026-07-11 181040" src="https://github.com/user-attachments/assets/d9052195-15fe-4d36-9796-789d1d354d39" />



`200 OK`. The server accepted the forged token and returned the admin panel HTML. The signature verification either wasn't performed or was performed incorrectly - the empty-key HS256 token was trusted as valid administrator credentials.

### Deleting the Target User

Sent `GET /admin/delete?username=carlos` with the same forged token.

**[SS6 - Burp Repeater: GET /admin/delete?username=carlos with forged JWT, response 302 Found, Location: /admin - delete action executed]**
<img width="1472" height="527" alt="Screenshot 2026-07-11 181229" src="https://github.com/user-attachments/assets/68fcf443-e196-4fb8-9745-ca5f953a021b" />



`302 Found` redirecting to `/admin`. The delete action executed server-side under the forged administrator identity.

**[SS7 - Burp Repeater Render tab: PortSwigger lab page "JWT authentication bypass via unverified signature" - LAB Solved banner, "User deleted successfully!", Users list showing only wiener remaining]**
<img width="1862" height="662" alt="Screenshot 2026-07-11 181249" src="https://github.com/user-attachments/assets/5c4cb541-3075-42c6-bf55-1698232d387a" />



Lab 1 solved. Carlos deleted. The entire admin function was accessed and executed with a JWT the legitimate administrator never issued.

---

## Lab 2 - JWT Authentication Bypass via Flawed Signature Verification (alg:none)

**Platform:** PortSwigger Web Security Academy

### The Original Token

Logged in again as `wiener:peter` on the second lab instance. Located the authenticated request and opened it in Burp Repeater, JWT Editor tab.

**[SS8 - Burp JWT Editor: original RS256 JWT on Repeater tab 2, Header showing "alg": "RS256", Payload showing "sub": "wiener", Signature bytes visible, Expiration Time in Information panel]**
<img width="947" height="900" alt="Screenshot 2026-07-11 182243" src="https://github.com/user-attachments/assets/c05e5b6e-51f7-43fb-a3a6-50278042cda8" />



Same starting point as Lab 1 - RS256 signed token, `sub: wiener`. Different attack this time.

### Stripping the Signature - alg:none

Changed `"alg": "RS256"` to `"alg": "none"`, changed `"sub": "wiener"` to `"sub": "administrator"`, and removed the signature entirely.

**[SS9 - Burp JWT Editor: modified JWT, Header showing "alg": "none", Payload showing "sub": "administrator", Signature section completely empty, Serialized JWT in the field showing the two-part token with trailing period and no signature - highlighted in red indicating unsigned]**
<img width="968" height="907" alt="Screenshot 2026-07-11 182645" src="https://github.com/user-attachments/assets/e165280c-0f70-4afc-9ff5-4ce237de1fe3" />



The serialized JWT now has the structure `header.payload.` - the trailing period is there but nothing follows it. No signature. The token makes a claim (`sub: administrator`) with zero cryptographic backing.

The `alg: none` attack works when the JWT library reads the algorithm from the token header and branches accordingly - if `none`, skip signature verification. A correctly implemented library should reject `none` as an invalid algorithm. This one didn't.

### Admin Panel Returned with No Signature

Sent `GET /admin` with the unsigned token.

**[SS10 - Burp Repeater: GET /admin with unsigned alg:none JWT in Cookie, response 200 OK, HTML response showing "JWT authentication bypass via flawed signature verification" in title tag, admin panel HTML content returned]**
<img width="1833" height="710" alt="Screenshot 2026-07-11 182724" src="https://github.com/user-attachments/assets/76a25000-ad1c-4a53-82cb-01904d16bc66" />



`200 OK`. The server processed the unsigned token, read `sub: administrator` from the payload, and returned the admin panel. No signature was verified because no signature was present and the server accepted that as valid.

### Deleting the Target User

Sent `GET /admin/delete?username=carlos` with the same unsigned token.

**[SS11 - Burp Repeater: GET /admin/delete?username=carlos with alg:none JWT, response 302 Found, Location: /admin]**
<img width="1477" height="498" alt="Screenshot 2026-07-11 183150" src="https://github.com/user-attachments/assets/0d2f2b43-2476-4872-8d53-7b1d755ab580" />



`302 Found`. Delete executed.

**[SS12 - Burp Repeater Render tab: PortSwigger lab page "JWT authentication bypass via flawed signature verification" - LAB Solved banner, "User deleted successfully!", Users list showing only wiener]**
<img width="1860" height="713" alt="Screenshot 2026-07-11 182815" src="https://github.com/user-attachments/assets/6c7c31d0-394d-4e54-9244-9b6978eb6f01" />



Lab 2 solved. Same outcome, different cryptographic failure.

---

## Comparing the Two Attacks

Both labs start with the same token (`RS256`, `sub: wiener`) and end with admin access and a deleted user. The path is different:

**Lab 1 - Algorithm Confusion:** The server accepts HS256 when the token was originally RS256. The forged token is signed with an empty key. The server's verification logic is loose enough to accept it - either it compares with an empty key or the verification is skipped for certain algorithm transitions.

**Lab 2 - alg:none Acceptance:** The server reads `alg: none` from the token header and skips verification entirely. The token carries a payload claim (`sub: administrator`) with no cryptographic proof. The server trusts it anyway.

In both cases the failure is the same category: the integrity of the authentication token is not properly verified before the claims inside it are trusted.

---

## The Full Attack Chains

**Lab 1:** Login as wiener → JWT issued in Set-Cookie → capture GET /my-account → send to Repeater → JWT Editor decodes RS256 token → change alg to HS256, sub to administrator → Sign with empty key → send GET /admin → 200 OK admin panel → send GET /admin/delete?username=carlos → 302 delete confirmed → lab solved.

**Lab 2:** Login as wiener → JWT issued → capture authenticated request → JWT Editor decodes RS256 token → change alg to none, sub to administrator → remove signature, preserve trailing period → send GET /admin → 200 OK admin panel returned → send GET /admin/delete?username=carlos → 302 delete confirmed → lab solved.

---

## What I Didn't Test But Exists

**JWT Secret Brute Force (HS256)**

If an application uses HS256 with a weak or default HMAC secret, the secret can be cracked offline. Tools like `hashcat` with mode `-m 16500` or `jwt_tool` take a valid signed token and attempt to recover the secret against a wordlist. A recovered secret allows signing any forged payload with a valid signature - harder to detect than algorithm confusion because the signature actually verifies.

**JWK Header Injection**

The JWT standard allows embedding a JWK (JSON Web Key) directly in the token header via the `jwk` parameter. If the server uses the embedded key to verify the token rather than a pre-configured trusted key, an attacker can generate their own RSA keypair, sign the token with the private key, and embed the public key in the `jwk` header. The server verifies successfully - against the attacker's own key.

**Kid Parameter Manipulation**

The `kid` (Key ID) header parameter tells the server which key to use for verification. In Lab 1 the `kid` was a UUID pointing to a specific key in the server's key store. If the server builds a file path or database query from `kid` without sanitizing it, this becomes an injection vector - `kid: "../../../../dev/null"` pointing to an empty file, or SQL injection in a `kid` used in a database lookup. Both can force verification against a null or attacker-controlled key.

**JWT Expiration Not Enforced**

Some implementations verify the signature but skip validating the `exp` claim. A token that should have expired hours ago remains valid indefinitely. This is a softer integrity failure - the token's time-based validity guarantee isn't enforced - but it enables persistent access using old tokens captured from traffic logs or previous sessions.

---

## Real Breaches This Maps To

**Auth0, 2015 (alg:none)** - Auth0's JWT library accepted tokens with `alg: none`, allowing any user to forge admin tokens by stripping the signature and setting any claim. The vulnerability was in the widely-used `node-jsonwebtoken` library and affected all applications depending on it. Patches were released but not all deployments updated promptly.

**Critical Infrastructure JWT Bugs, 2022** - Researchers found multiple industrial control system web interfaces using JWT authentication that accepted `alg: none` tokens. A compromised network position would allow forging operator tokens and sending commands to physical systems - same attack, different stakes.

**Portswigger Research** - The algorithm confusion attack (RS256→HS256) was documented and popularized by PortSwigger's own research team. They identified it in multiple real-world applications and JWT libraries before publishing the attack methodology - which is why these labs exist.

---

## Remediation

| Issue | Fix |
|---|---|
| Algorithm confusion (RS256→HS256) | Pin the expected algorithm server-side in code - `jwt.verify(token, key, { algorithms: ['RS256'] })`; never read the algorithm from the token header |
| alg:none acceptance | Explicitly reject `none` as an algorithm; maintain an allowlist of permitted algorithms and refuse anything not on it |
| Empty key acceptance | Validate that the signing key is non-null and meets minimum length requirements before verification |
| Kid parameter unsanitized | Treat `kid` as untrusted input; validate it against a known set of key IDs; never use it to build file paths or SQL queries |
| Expired tokens accepted | Always validate the `exp` claim after signature verification; reject expired tokens regardless of signature validity |

---

## Three Takeaways

The algorithm field in a JWT header should never be trusted. It's attacker-controlled data. The server should decide which algorithm to use based on its own configuration, not based on what the token claims. Reading `alg` from the incoming token and branching on it is the architectural mistake that makes both labs possible.

No signature and a wrong signature should produce the same result - rejection. `alg:none` works because the server treats "no signature required" as a valid state rather than an error. A correct implementation has one valid path: verified signature with an approved algorithm. Everything else is a rejection.

Both attacks end identically despite using different techniques. Algorithm confusion and `alg:none` are different exploits but the same root failure: the server cannot guarantee that the claims in the token were placed there by a trusted issuer. Once that guarantee breaks, every claim in the payload is attacker-controlled - including `sub: administrator`.

---

> **Lab:** PortSwigger Web Security Academy - JWT Labs | **Tools:** Burp Suite Professional, Burp JWT Editor Extension | **Category:** OWASP A08:2021 - Software and Data Integrity Failures
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
