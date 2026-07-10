# OWASP Top 10 Labs Series #1 - A01: Broken Access Control

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. This is entry #1 - the top-ranked vulnerability in the OWASP list. Follow along for A01 through A10.

---

## The Bug - What Is A01 Broken Access Control?

Access control is supposed to answer one question: is this user allowed to do this? Broken access control means the answer is supposed to be "no" but the application never actually checks - or checks in a way that's trivially bypassable.

OWASP ranks this #1 because it's the most common critical finding in real-world applications. It doesn't require sophisticated exploitation. It usually just requires changing a number in a URL or navigating to a path the developer assumed nobody would guess.

This lab covers three bugs across two Juice Shop instances - an IDOR on the basket API, unauthorized access to the admin panel, and a hidden route discovered through client-side source code inspection.

---

## Bug 1 - IDOR: Reading Another User's Basket

### What IDOR Is

Insecure Direct Object Reference means the application uses a user-controllable identifier - like a numeric ID - to look up a resource, and never checks whether the requesting user is actually authorized to see it.

### Finding the Request

Logged in, added a product to the basket, then checked Burp HTTP History for the basket API call.

**[SS1 - Burp HTTP History: GET /rest/basket/6 highlighted, status 304, JWT in Authorization header and Cookie visible in the request]**
<img width="1492" height="822" alt="Screenshot 2026-07-10 193508" src="https://github.com/user-attachments/assets/d6fa675a-4018-45a1-bcfe-c223dbf2dbab" />



The app called `GET /rest/basket/6` to load my basket. The basket ID is a sequential integer sitting in the URL path. No object-level authorization check visible anywhere in the request. Sent it to Repeater.

### Changing the ID

Modified the basket ID from `6` to `1`.

**[SS2 - Burp Repeater: GET /rest/basket/1, response 200 OK, body shows basket id:1, UserId:1, Products array containing Apple Juice (1000ml) at price 1.99]**
<img width="1432" height="712" alt="Screenshot 2026-07-10 193812" src="https://github.com/user-attachments/assets/ac088b72-fc50-48d7-b1b5-e7060d1ca5bf" />



`200 OK`. Someone else's basket, contents and all. `UserId:1` in the response - that's the admin's basket. My session token was valid for my account, but the server never checked whether basket 1 belonged to me.

### Confirming It's Systemic

Tried another ID.

**[SS3 - Burp Repeater: GET /rest/basket/2, response 200 OK, body shows basket id:2, UserId:2, Products array with Raspberry Juice (1000ml) at price 4.99]**
<img width="1431" height="721" alt="Screenshot 2026-07-10 193933" src="https://github.com/user-attachments/assets/47bc12fb-0e4a-48be-bb7d-402667f9e377" />



Different basket, different user, different contents. Still `200 OK`. The absence of authorization checks isn't a one-off - it's consistent across every basket ID. Any logged-in user can enumerate all baskets in the database by simply incrementing the ID.

In a real e-commerce application, this exposes purchase history, saved payment methods, and personal information for every user. One API call per ID is all it takes.

---

## Bug 2 - Forced Browsing: Admin Panel With No Auth Check

### Accessing the Administration Route Directly

Navigated directly to:

```
http://localhost:3000/#/administration
```

No credentials required. No admin role check. The page loaded.

**[SS4 - Browser: Juice Shop Administration page at localhost:3000/#/administration, challenge solved banner "Admin Section" visible, Registered Users list showing admin@juice-sh.op, jim@juice-sh.op, bender@juice-sh.op, bjoern.kimminich@gmail.com, ciso@juice-sh.op and others, Customer Feedback section on the right with delete controls]**
<img width="1918" height="945" alt="Screenshot 2026-07-10 200012" src="https://github.com/user-attachments/assets/d4483ec9-6216-487a-bab8-59cc7f9b4c8d" />



The full administration panel - registered user list with email addresses, customer feedback with delete controls - accessible to anyone who knows the URL. The route existed, the page rendered, and the backend APIs served privileged data because the only protection was that the link wasn't in the navigation menu.

### Backend APIs Confirm No Server-Side Enforcement

Opened DevTools Network tab and watched the requests fire when the admin page loaded.

**[SS5 - DevTools Network: /api/Feedbacks/ request highlighted showing 304 status, Response tab showing JSON with status "success", data array containing all customer feedback objects with comments, ratings, and partially masked user emails]**
<img width="1912" height="971" alt="Screenshot 2026-07-10 200722" src="https://github.com/user-attachments/assets/35d2539f-91f4-4ea5-93fd-fb94e6ed92f9" />



`GET /api/Feedbacks/` returned the full feedback dataset. The server didn't verify admin role server-side - it just returned the data. Hiding the link in the UI is not access control. The API needs to enforce authorization independently. Here it doesn't.

---

## Bug 3 - Hidden Route Discovery via Client-Side Source

### Accessing the Score Board Directly

Navigated to:

```
http://localhost:3000/#/score-board
```

The Juice Shop score board - a hidden page listing all challenges - loaded without any authentication or privilege requirement.

**[SS6 - Browser: Juice Shop Score Board page at 10.49.139.206/#/score-board, showing 3/172 Challenges Solved, 3% progress, challenge categories including XSS, Sensitive Data Exposure, Broken Access Control, Injection, Security Misconfiguration visible as filter tags, individual challenge cards listed below]**
<img width="1918" height="967" alt="Screenshot 2026-07-10 201432" src="https://github.com/user-attachments/assets/f5aba273-e6fc-4ee6-a44a-fb1035d05d25" />



The page itself is the finding - a route that the application treats as hidden but imposes no access control on. But the more interesting question is how an attacker would discover it without being told.

### Finding It in the JavaScript Bundle

Opened DevTools → Debugger → `main.js` and searched for `score-board`.

**[SS7 - DevTools Sources: main.js open in debugger, line 29031 highlighted showing path: 'score-board' with component: Qd, surrounded by other route definitions including search, hacking-instructor, track-result - full client-side route table visible]**
<img width="1537" height="917" alt="Screenshot 2026-07-10 201659" src="https://github.com/user-attachments/assets/aaf91240-b864-48e0-9cc3-a8b8d6d96d2c" />



Line 29031. The entire client-side routing table is compiled into the JavaScript bundle that gets delivered to every visitor. Every route the application knows about - including ones with no navigation link - is readable by anyone who opens DevTools and searches the source.

This is the recon step that makes forced browsing systematic rather than lucky. An attacker doesn't need to guess paths. They load the app, open the JS bundle, and extract the complete route map. From there, every hidden endpoint becomes a target for access control testing.

---

## The Full Attack Chain

Basket IDOR: Log in → observe `GET /rest/basket/6` in Burp → send to Repeater → change ID to `1` → 200 OK returns admin basket → increment IDs → full user basket enumeration confirmed.

Admin panel: Navigate to `/#/administration` → page loads → DevTools confirms `/api/Feedbacks/` returns privileged data with no server-side auth check → full user list and feedback accessible.

Hidden route: Open `main.js` in DevTools → search `score-board` → route definition found at line 29031 → navigate directly → hidden challenge page loads with no access control.

---

## What I Didn't Test But Exists

**Horizontal vs Vertical Privilege Escalation**

The basket IDOR is horizontal escalation - same privilege level, different user's data. Vertical escalation would be using a regular user account to access admin-only functionality. Both fall under A01. The administration panel bug here is technically vertical - a non-admin reaching admin functionality - but only because the app never checks the role server-side.

**Mass Assignment**

Juice Shop's REST API accepts JSON bodies for user updates. If the API doesn't strip fields like `isAdmin` or `role` before writing to the database, you can include them in a registration or profile update request and assign yourself elevated privileges directly. This is A01 at the data layer - the object takes whatever you give it without validating which fields you're allowed to modify.

**JWT Role Manipulation**

The app issues JWTs containing user data. If the signature algorithm is weak or the secret is guessable, modifying the token payload to change `role` to `admin` and re-signing it could grant admin access without exploiting any specific endpoint. Combined with the algorithm confusion issues from A07, this extends the access control attack surface to the token itself.

**API Endpoint Enumeration**

The `/api/Feedbacks/` endpoint was one of many APIs the admin page called. A systematic approach would enumerate all REST endpoints visible in the JS bundle and Burp history, then test each one from a low-privilege account to see which ones return data or perform actions they shouldn't.

**Function-Level Access Control**

Beyond viewing data, admin endpoints often perform destructive actions - delete user, reset feedback, change prices. Each of these needs its own authorization check. It's common for applications to protect the read endpoints and forget the write/delete ones, or vice versa. Testing the full CRUD surface on privileged endpoints is standard A01 methodology.

---

## Real Breaches This Maps To

**Facebook, 2019** - IDOR vulnerabilities in Facebook's photo API allowed attackers to access photos from private albums and stories by manipulating media IDs in API requests. The pattern is identical to the basket ID manipulation here.

**Parler, 2021** - After Parler was taken down and then restored, researchers found that post IDs were sequential and publicly accessible without authentication. Every post, including deleted ones, could be enumerated by incrementing the ID. Millions of posts and associated metadata were archived using nothing more than a loop and an HTTP client.

**Optus Australia, 2022** - An unauthenticated API endpoint exposed customer data including passport and licence numbers for 9.8 million customers. No authentication required - the endpoint was simply accessible to anyone who found it. Forced browsing to an unprotected API, at scale.

---

## Remediation

| Issue | Fix |
|---|---|
| IDOR on basket API | Enforce object-level authorization server-side: verify the authenticated user's ID matches the basket's `UserId` before returning data |
| Admin panel accessible via direct URL | Implement role-based access control middleware on the route; check `isAdmin` or equivalent role claim server-side on every request |
| Admin APIs returning data without auth check | Authorization must be enforced at the API layer independently of the frontend - the UI hiding a link is not a security control |
| Hidden routes discoverable in JS bundle | Sensitive route paths alone aren't a vulnerability, but every route must have server-side access control; audit all routes in the bundle against their backend enforcement |
| No consistent authorization model | Implement a centralized authorization middleware that applies to every endpoint by default; opt-out for public routes rather than opt-in for protected ones |

---

## Three Takeaways

Sequential IDs with no authorization check are an enumeration attack waiting to happen. Basket ID 1 through however many users exist - that's the entire customer order history of the application, accessible with a loop and a valid session token. Object-level authorization needs to be checked on every request, not assumed from the URL pattern.

Hiding a link is not the same as protecting a route. The admin panel at `/#/administration` had no navigation link pointing to it. The API endpoints it called had no server-side role verification. Both layers failed independently. Real access control means the server refuses unauthorized requests regardless of whether the client was supposed to know the endpoint existed.

The JavaScript bundle is a recon document. Every route in `main.js` is delivered to every visitor before they authenticate. An attacker enumerating the application doesn't start from a blank page - they start from the complete client-side route map compiled into the bundle. That map should inform which endpoints get hardened, not which ones get hidden.

---

> **Lab:** OWASP Juice Shop (TryHackMe instance + local, 10.49.139.206 / localhost:3000) | **Tools:** Burp Suite Community, Browser DevTools | **Category:** OWASP A01:2021 - Broken Access Control
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
