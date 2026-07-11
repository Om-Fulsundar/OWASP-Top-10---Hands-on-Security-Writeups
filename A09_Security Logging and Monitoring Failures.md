# OWASP Top 10 Labs Series - A09: Security Logging and Monitoring Failures - Race Conditions That Fly Under the Radar

> **Series:** This is the final entry in my OWASP Top 10 Labs Series. I've worked through all ten vulnerability categories hands-on across Juice Shop and PortSwigger, documenting each one. A09:2021 covers Security Logging and Monitoring Failures. These two labs approach it from a different angle than most - instead of showing missing logs, they show what happens when high-speed concurrent abuse goes undetected by the security controls that should catch it. Follow along for the full A01 through A10 series.

---

## The Bug - What Is A09 Security Logging and Monitoring Failures?

A09 is about detection and response, not the attack itself. An application can have logging in place and still fail at A09 if the logs don't capture the right events, aren't monitored in real time, or if the alerting thresholds are so coarse that a burst of identical concurrent requests gets through without triggering anything.

Race conditions are the perfect example. The application has a security control - a coupon usage limit, a login rate limiter - and both controls work fine against sequential abuse. They're completely blind to parallel abuse that lands within milliseconds. The requests arrive, get processed before any shared state updates, and the logs show a handful of "accepted" entries that look indistinguishable from normal traffic at first glance.

Two labs, two different race windows. Both demonstrate that controls without proper concurrency awareness - and monitoring without burst detection - are not real controls at all.

---

## Lab 1 - Limit Overrun Race Conditions

**Platform:** PortSwigger Web Security Academy

### The Coupon Redemption Request

Logged in as `wiener:peter`, added the Lightweight "l33t" Leather Jacket to the cart, and applied the promotional code `PROMO20`. Burp Intercept caught the redemption request.

**[SS1 - Burp Intercept: POST /cart/coupon intercepted, request body showing csrf token and coupon=PROMO20, URL pointing to the web-security-academy.net lab instance]**
<img width="1442" height="825" alt="Screenshot 2026-07-12 005610" src="https://github.com/user-attachments/assets/d5e55c8b-1f21-4490-9ae8-961c8f566bf5" />



`POST /cart/coupon` with `coupon=PROMO20`. One request, one redemption. The intended behavior: coupon applies once, usage counter increments, any subsequent attempt returns an error. The actual behavior relies on that counter updating fast enough to reject the next request before it arrives.

### Building the Parallel Attack

Sent the request to Repeater and duplicated it into a group of 26 identical requests. Set the send mode to "Send group (parallel)."

**[SS2 - Burp Repeater: group named "race" with 26 tabs visible (tab 46 active, tabs 47 through 71 visible), "Send group (parallel)" button highlighted, POST /cart/coupon request in the pane with coupon=PROMO20]**
<img width="1868" height="712" alt="Screenshot 2026-07-12 005702" src="https://github.com/user-attachments/assets/c1264a2e-6053-45d9-8ce5-755c9d35d0ce" />



26 copies of the same coupon redemption request, queued to fire simultaneously over HTTP/2. The key detail is HTTP/2 - it multiplexes multiple requests over a single connection, minimizing the timing gap between them landing at the server. This is what makes the single-packet attack effective: all 26 requests arrive close enough together that several get processed before the coupon usage state updates.

### Multiple Coupons Accepted

Fired the group in parallel.

**[SS3 - Burp Repeater: same group after send, response panel showing HTTP/2 302 Found, Location: /cart, response body "Coupon applied" - one of multiple successful responses from the parallel attack]**
<img width="1773" height="707" alt="Screenshot 2026-07-12 005729" src="https://github.com/user-attachments/assets/585ac52f-06c8-4cf4-b898-94e61356ede2" />



`302 Found`. "Coupon applied." This was one of multiple identical successful responses - several of the 26 parallel requests hit the server within the race window and were each accepted before the counter had a chance to increment and block further use.

### The Discounted Cart

Refreshed the browser cart.

**[SS4 - Browser: cart page showing Lightweight "l33t" Leather Jacket at $1337.00, PROMO20 coupon applied with -$1312.93 reduction, Total: $24.07, Place order button visible]**
<img width="1282" height="946" alt="Screenshot 2026-07-12 005752" src="https://github.com/user-attachments/assets/ed5bb573-151c-43dd-b25b-d3da7e288812" />



The coupon applied multiple times in rapid succession, stacking the discounts. A 20% coupon meant to take $267 off a $1337 jacket instead reduced it by $1312.93 - a 98% discount. The total dropped to $24.07.

Placed the order.

**[SS5 - Browser: PortSwigger "Limit overrun race conditions" - LAB Solved banner, order confirmation showing Lightweight "l33t" Leather Jacket $1337.00, Total: $24.07, Store credit: $25.93]**
<img width="1918" height="758" alt="Screenshot 2026-07-12 005823" src="https://github.com/user-attachments/assets/ab405267-a86d-4ad5-9699-3fc087200039" />



Lab 1 solved. A $1337 jacket purchased for $24.07 by sending the same coupon 26 times in parallel. The application logged each "Coupon applied" event individually. Without burst detection - without correlation of multiple identical requests from the same session within the same millisecond window - nothing in those logs would flag this as anomalous.

---

## Lab 2 - Bypassing Rate Limits via Race Conditions

**Platform:** PortSwigger Web Security Academy

### Confirming the Rate Limiter Exists

Made multiple failed login attempts against `carlos` sequentially to confirm the lockout mechanism was active.

**[SS6 - Browser: "Bypassing rate limits via race conditions" lab login page showing error "You have made too many incorrect login attempts. Please try again in 56 seconds." - lockout enforced after sequential failed attempts]**
<img width="1918" height="801" alt="Screenshot 2026-07-12 010657" src="https://github.com/user-attachments/assets/2dec83d8-988f-4b04-8171-63583f302866" />



The lockout is real. Sequential brute force is blocked. The rate limiter tracks failed attempts per username and enforces a cooldown. The question is whether it can track concurrent requests arriving simultaneously before any of them increment the counter.

### Configuring Turbo Intruder

The Burp Repeater parallel approach works for a small group. For a full password list attack within a single race window, Turbo Intruder is the right tool. Sent the login request to Turbo Intruder, set `username=carlos` and `password=%s` as the payload marker, loaded `wordlists.clipboard` as the password list, and configured the gate-based single-packet HTTP/2 race script.

**[SS7 - Turbo Intruder: request pane showing POST /login with username=carlos and password=%s in line 20, script pane showing queueRequests function using Engine.BURP2 with concurrentConnections=1, passwords from wordlists.clipboard queued with gate='1', engine.openGate('1') releasing all requests simultaneously]**
<img width="1556" height="772" alt="Screenshot 2026-07-12 011110" src="https://github.com/user-attachments/assets/0123818c-b3dd-482d-a1ed-2c2bba8ae416" />



The script queues every password attempt behind a gate, then opens it - releasing all requests simultaneously over a single HTTP/2 connection. The entire password list fires at once. The rate limiter sees the first attempt, starts to record it, but the remaining attempts are already being processed before the lockout state has propagated.

### The 302 in the Results

Turbo Intruder returned results. Most responses were 200 (wrong password shown on the login page) or 400. One row stood out.

**[SS8 - Turbo Intruder results table: Row 1 payload "abc123" with Status 302, Length 42,691 highlighted in blue at the top - distinctly different from all other rows showing 200 or 400 status, response pane showing HTTP/2 302 Found with Location: /my-account?id=carlos and Set-Cookie issuing a session]**
<img width="1847" height="905" alt="Screenshot 2026-07-12 012558" src="https://github.com/user-attachments/assets/d1ea4867-9aac-47bd-b494-40277b63f884" />



Row 1: `abc123`. Status `302 Found`. Every other password returned a consistent response - this one redirected to `/my-account?id=carlos` and issued a new session cookie. That's the correct password.

The race window allowed all passwords in the list to be attempted before the lockout counter reached its threshold. The rate limiter was counting correctly - but it was counting slower than the requests were arriving.

### Logged In as Carlos

Waited for the lockout period to expire, then logged in with `carlos` / `abc123`.

**[SS9 - Browser: "Bypassing rate limits via race conditions" lab, My Account page showing "Your username is: carlos", "Your email is: carlos@carlos-montoya.net", Admin panel link visible in navigation - Lab Not solved banner still showing (logged in, about to delete)]**
<img width="1792" height="772" alt="Screenshot 2026-07-12 012708" src="https://github.com/user-attachments/assets/b10bed5f-9a6e-4768-90ee-378f0591ab18" />



Logged in as carlos. Admin panel visible in the nav.

### Admin Panel - Deleting Carlos

Navigated to the admin panel.

**[SS10 - Browser: Admin panel at /admin, Users section showing "wiener - Delete" and "carlos - Delete" - both users listed, carlos delete link accessible]**
<img width="1625" height="606" alt="Screenshot 2026-07-12 012726" src="https://github.com/user-attachments/assets/5f1cdf84-aad8-48d4-aedc-02d48077bef6" />



Both users listed. Clicked Delete next to carlos.

**[SS11 - Browser: "Bypassing rate limits via race conditions" - LAB Solved banner, "Admin interface only available if logged in as an administrator", timer showing 04:18]**
<img width="1750" height="532" alt="Screenshot 2026-07-12 012735" src="https://github.com/user-attachments/assets/062a9a14-ea96-43c6-b4f3-159bf9b781b3" />



Lab 2 solved. A rate-limited account that should have been impossible to brute force was cracked in a single parallel request burst. The lockout fired after the fact. The correct password was already identified.

---

## The Full Attack Chains

**Lab 1:** Intercept POST /cart/coupon → duplicate to 26 Repeater tabs → Send group in parallel over HTTP/2 → multiple 302 "Coupon applied" responses before usage counter updates → coupon stacked repeatedly → $1337 jacket at $24.07 → lab solved.

**Lab 2:** Confirm sequential lockout fires → send POST /login to Turbo Intruder → username=carlos, password=%s, wordlists.clipboard → gate-based HTTP/2 race script queues entire list → openGate releases all simultaneously → one 302 response identifies `abc123` before lockout propagates → wait for cooldown → login with recovered credentials → admin panel → delete carlos → lab solved.

---

## The Monitoring Failure - What A09 Actually Means Here

Both applications had security controls. The coupon system enforced single-use. The login form had a lockout. Neither control was absent.

The failure is that neither control was designed for concurrent requests, and neither monitoring system was designed to detect the attack pattern. From a logging perspective:

In Lab 1, the logs show multiple "Coupon applied" events in rapid succession from the same session. Sequential tooling would catch this immediately. A properly configured SIEM rule watching for more than one coupon redemption event per session within a short time window would have flagged it - but that rule wasn't there.

In Lab 2, the logs show dozens of login attempts for `carlos` arriving within milliseconds of each other. A rate limiter that counts sequentially will eventually fire, but the burst happened faster than the counter. A SIEM alert watching for more than N login attempts per username within a sub-second window - correlated across concurrent connections - would catch this. Without that correlation, the logs just show a bunch of failed attempts and one success, which looks like a user eventually got their password right.

The security control existed. The detection and monitoring to catch its bypass did not.

---

## What I Didn't Test But Exists

**Race Conditions on Financial Transfers**

The coupon pattern generalizes to any balance-check-then-debit operation: gift card redemption, loyalty point spending, wallet transfers. If the check and the debit aren't atomic - if there's any window between "is there enough balance?" and "deduct the balance" - parallel requests can each pass the check before any of them deducts anything. The Starbucks race condition in 2015 exploited exactly this pattern on gift card transfers.

**TOCTOU in File Operations**

Time-of-check to time-of-use races extend beyond HTTP. File upload validation, virus scanning on upload, permission checks before write operations - anywhere the check and the use are separate steps, a race can be injected between them. An attacker replaces a safe file with a malicious one in the window between the validation check and the actual processing.

**Race Conditions in Password Reset Flows**

Some password reset implementations generate a token, store it, and then send it by email - sequentially. If the token generation step doesn't properly lock the account state, sending multiple simultaneous reset requests can result in multiple valid tokens being issued. Only one gets emailed, but all are valid in the database.

**Database-Level Fixes**

The correct fix for most of these isn't application-level locking - it's atomicity at the database layer. Transactions with proper isolation levels, `SELECT ... FOR UPDATE`, atomic `UPDATE ... WHERE old_value = expected_value` patterns. Application-level checks with separate database writes will always have a window. The window might be microseconds, but parallel HTTP/2 requests can fit in microseconds.

---

## Real Breaches This Maps To

**Starbucks, 2015** - Researchers demonstrated a race condition in Starbucks gift card transfers where sending multiple simultaneous transfer requests allowed the same balance to be transferred to multiple accounts. The money multiplication worked because the balance check and the debit weren't atomic. Starbucks patched it after responsible disclosure.

**HackerOne Bug Bounty Duplicates, recurring** - Race conditions in coupon, referral, and credit systems have been reported against major platforms including Shopify, GitLab, and various e-commerce companies. Many were discovered specifically through parallel request attacks identical to what Lab 1 demonstrates.

**Robinhood, 2019** - A race condition in Robinhood's margin trading system allowed users to leverage far more capital than they had deposited by executing trades simultaneously before positions settled. Users exploited this intentionally before it was patched, executing what amounted to trades with unlimited margin.

---

## Remediation

| Issue | Fix |
|---|---|
| Coupon reuse via race window | Enforce redemption atomically using a database transaction with a unique constraint or `UPDATE ... WHERE used = false` pattern; the check and the flag must be a single atomic operation |
| Rate limiter bypassed by concurrent requests | Implement distributed rate limiting with atomic counters (Redis `INCR` with `EXPIRE`); check and increment must be a single atomic operation |
| No burst detection in monitoring | Alert on multiple identical requests from the same session or IP within sub-second windows; correlate concurrent connections, not just sequential counts |
| HTTP/2 multiplexing not accounted for | Test all stateful endpoints with parallel HTTP/2 requests during security review; single-threaded test tooling misses concurrency vulnerabilities |

---

## Three Takeaways - And a Series Wrap

Security controls that work sequentially aren't necessarily secure. Both labs had functioning controls - a coupon limit, a lockout. Both controls operated on the assumption that requests arrive one at a time and state updates between them. That assumption breaks entirely under parallel load, and the controls evaporate.

Logging what happened isn't the same as detecting what happened. The coupon redemption events were logged. The login attempts were logged. The information to detect the attacks was there. The correlation logic and alerting thresholds to turn those logs into signals were not. A09 isn't about empty log files - it's about the gap between having data and having visibility.

And the series wrap: ten categories, ten labs, documented end to end. A01 through A10 - access control failures, cryptographic mistakes, injection, insecure design, misconfiguration, outdated components, authentication failures, software integrity, logging gaps, SSRF - each one demonstrated with real tools against real lab environments, not theory. The goal was always to build something a portfolio reviewer could actually follow: here's the bug, here's what I did, here's what it means. That's what these writeups are.

---

> **Lab:** PortSwigger Web Security Academy - Race Condition Labs | **Tools:** Burp Suite Professional, Burp Turbo Intruder Extension | **Category:** OWASP A09:2021 - Security Logging and Monitoring Failures
>
> *This is the final entry in my OWASP Top 10 Labs Series. All ten categories documented. A01 through A10 - complete.*
