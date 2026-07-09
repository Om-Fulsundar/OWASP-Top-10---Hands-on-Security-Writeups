# OWASP Top 10 Labs Series #3 - A03: Injection - SQL Injection, Data Extraction, and HTML Injection

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. This is entry #3. Follow along for A01 through A10.

---

## The Bug - What Is A03 Injection?

Injection happens when user-supplied input is interpreted as a command instead of data. The application takes what you type, drops it directly into a query or interpreter, and executes it. SQL injection, HTML injection, command injection - all the same root problem, different interpreters.

This lab covers three bugs across two attack surfaces: a login form and a search endpoint. Between them they demonstrate authentication bypass, full database extraction, and reflected HTML injection - the full range of what A03 looks like in practice.

---

## Bug 1 - SQL Injection Login Bypass

### The Idea

The login form sends an email and password to the server, which builds a SQL query like:

```sql
SELECT * FROM Users WHERE email = '[input]' AND password = '[hash]'
```

If the input isn't sanitized, injecting SQL syntax into the email field can manipulate the logic of that query entirely.

### Intercepting the Request

Turned on Burp intercept, entered `' OR 1=1--` in the email field and `anything` as the password, and clicked Login.

**[SS1 - Burp Intercept: POST /rest/user/login intercepted, request body shows email: "' OR 1=1--", password: "anything"]**
<img width="1353" height="818" alt="Screenshot 2026-07-09 145859" src="https://github.com/user-attachments/assets/e9327b6f-0683-4269-b217-4926d99f4247" />



The payload breaks the query into:

```sql
SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = '...'
```

`OR 1=1` is always true. The `--` comments out the rest of the query including the password check. The database returns the first user - which is the admin.

Forwarded the request.

### Result - Admin Access, No Password

**[SS2 - Browser: Juice Shop homepage loaded, Account dropdown showing "admin@juice-sh.op" as the logged-in user]**
<img width="1918" height="420" alt="Screenshot 2026-07-09 150000" src="https://github.com/user-attachments/assets/b799905a-1993-4019-8c18-f089d7fe5cbb" />


Logged in as `admin@juice-sh.op` without knowing the password. The entire authentication mechanism was bypassed with six characters.

### Confirming the Response

Checked HTTP History for the login response.

**[SS3 - Burp HTTP History: POST /rest/user/login highlighted with 200 OK, response body showing JWT token and "umail":"admin@juice-sh.op" in the authentication object]**
<img width="1918" height="827" alt="Screenshot 2026-07-09 150231" src="https://github.com/user-attachments/assets/5014c3f2-f3a3-49f0-aa2b-5dc180ac5b19" />



The server returned a full JWT token and confirmed the authenticated identity as `admin@juice-sh.op`. The token is now usable for any subsequent authenticated requests.

---

## Bug 2 - UNION-Based SQL Injection Data Extraction

The login bypass was one SQL injection point. The search endpoint is another - and this one allows data extraction from the database directly.

### Confirming the Injection Point

The search bar fires:

```
GET /rest/products/search?q=[input]
```

In Burp Repeater, tested with `test'))--` to check whether the parameter was injectable.

**[SS4 - Burp Repeater: GET /rest/products/search?q=test'))-- with 200 OK response, body shows status "success", data array empty - query executed without error]**
<img width="1420" height="523" alt="Screenshot 2026-07-09 150703" src="https://github.com/user-attachments/assets/283fccfd-00e7-4a8d-bd04-d8eda76f93ae" />



Empty result, no error. The payload closed the query syntax correctly and the `--` commented out the rest. The parameter is injectable.

### Column Enumeration with UNION SELECT

UNION injection requires knowing the number of columns the original query returns. Tried:

```sql
test')) UNION SELECT 1,2,3,4,5,6,7,8,9--
```

**[SS5 - Burp Repeater: UNION SELECT 1,2,3,4,5,6,7,8,9 payload in request, response shows 200 OK with data object containing id:1, name:2, description:3, price:4, deluxePrice:5, image:6, createdAt:7, updatedAt:8, deletedAt:9]**
<img width="1425" height="641" alt="Screenshot 2026-07-09 151146" src="https://github.com/user-attachments/assets/748479f9-51ad-4196-a707-381a6ba5e389" />



The response returned a product object where each field mapped directly to the numbered column positions. Nine columns confirmed. The field names in the response - `id`, `name`, `description`, `price` - told me exactly which column position maps to which database field. That's the column map needed to extract real data.

### Extracting User Credentials

With the column count confirmed, replaced the placeholder numbers with actual fields from the `Users` table:

```sql
test')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--
```

**[SS6 - Burp Repeater: UNION SELECT with id, email, password FROM Users payload, response shows multiple user objects with email addresses and password hashes - admin@juice-sh.op, jim@juice-sh.op, bender@juice-sh.op, bjoern.kimminich@gmail.com and others visible with MD5 hashes in the description field]**
<img width="1841" height="660" alt="Screenshot 2026-07-09 151738" src="https://github.com/user-attachments/assets/d55ad965-1bbb-4b2c-9195-a50cd1f76fae" />



The response returned every user in the database - emails, IDs, and password hashes for all accounts. `admin@juice-sh.op`, `jim@juice-sh.op`, `bender@juice-sh.op`, `bjoern.kimminich@gmail.com` - the full user list dumped in a single request.

### Cracking the Hash

Copied the admin hash: `0192023a7bbd73250516f069df18b500`. Pasted it into CrackStation.

**[SS7 - CrackStation: hash 0192023a7bbd73250516f069df18b500 identified as MD5, result column shows "admin123" in green - exact match]**
<img width="1332" height="402" alt="Screenshot 2026-07-09 151842" src="https://github.com/user-attachments/assets/555acb7e-60ca-42f4-a5ed-3b85b1282b27" />



MD5. Cracked instantly to `admin123`. A password hash stored with no salting, in a format that's been deprecated for credential storage since the early 2000s, cracked by a public lookup table in under a second.

At this point the attack chain is complete: login bypass to get in, UNION injection to dump the database, hash cracking to recover plaintext credentials. Everything needed for persistent access.

---

## Bug 3 - HTML Injection via Search

This one is different from the SQL bugs. No database involved - the search input is reflected directly into the page without output encoding, so the browser renders whatever HTML you inject.

### Injecting the Payload

Entered the following in the search bar:

```html
<h1 style="color:red"> HTML Injection Successful </h1>
```

**[SS8 - Browser: Juice Shop search results page showing "Search Results -" followed by "HTML Injection Successful" rendered in large red heading text, URL bar shows the encoded payload]**
<img width="1912" height="312" alt="Screenshot 2026-07-09 163322" src="https://github.com/user-attachments/assets/3c956a99-14bf-4814-94c1-ead16ffa0010" />



The app reflected the input back into the page and the browser rendered it as a heading element with inline CSS styling. The text "HTML Injection Successful" displayed in red. No sanitization, no encoding.

### Confirming in the DOM

Opened DevTools and inspected the element.

**[SS9 - DevTools Elements panel: DOM tree showing span#searchValue containing the raw  < h1 style="color:red">HTML Injection Successful </ h1> element as a child node, rendered heading visible in the page above]**

<img width="1917" height="802" alt="Screenshot 2026-07-09 163659" src="https://github.com/user-attachments/assets/de4f862c-9ff6-4aa9-8851-6e6e6d551eb8" />



The `<h1>` tag is sitting inside `span#searchValue` as a live DOM element. The browser treated the injected string as markup, not text. In a real application, this is the entry point for phishing overlays, credential harvesting forms, and if JavaScript were injectable here, stored XSS leading to session theft.

---

## The Full Attack Chain

`' OR 1=1--` in email field → SQL query logic bypassed → admin session issued → JWT token captured → search endpoint identified → `test'))--` confirms injection → UNION SELECT 9 columns maps the schema → `UNION SELECT id,email,password FROM Users` dumps all credentials → MD5 hash cracked to `admin123` → HTML payload injected via search → `<h1>` renders in DOM → output encoding confirmed absent.

Three bugs, two attack surfaces, one coherent story of what happens when user input is trusted anywhere in the stack.

---

## What I Didn't Test But Exists

**Blind SQL Injection**

The UNION approach works here because the response reflects query results. In a blind SQLi scenario the app doesn't return data - it just behaves differently depending on whether a condition is true or false. Boolean-based blind: `' AND 1=1--` vs `' AND 1=2--` and observe the difference. Time-based blind: `' AND SLEEP(5)--` and measure the response delay. Same vulnerability, no visible output, harder to exploit but still fully automatable with `sqlmap`.

**Stored vs Reflected HTML Injection**

What I demonstrated was reflected - the payload lives in the URL and only affects the user who visits that URL. Stored injection is worse: the payload gets saved to the database and executes for every user who loads that page. In Juice Shop, product reviews and feedback fields are candidates for stored injection. If those fields aren't sanitized before being written to the database, a single submission affects every visitor.

**Escalating HTML Injection to XSS**

HTML injection and XSS are on the same spectrum. HTML injection means you control markup. XSS means you control script. If `<script>` tags aren't filtered - or if event handlers like `<img src=x onerror=alert(1)>` work - HTML injection becomes XSS. From there: cookie theft, session hijacking, keylogging, full account takeover without needing credentials.

**NoSQL Injection**

MongoDB and other NoSQL databases have their own injection patterns. Instead of SQL syntax, you inject operator objects: `{"$gt": ""}` in a JSON body can bypass authentication in the same way `' OR 1=1--` does in SQL. The principle is identical - user input gets interpreted as a query operator. Juice Shop's REST API uses JSON bodies throughout, making this a realistic test target.

**ORM Injection**

Juice Shop uses Sequelize as its ORM. Properly parameterized ORM queries are injection-safe, but raw query methods or string concatenation inside an ORM still produce injectable SQL. The fact that UNION injection worked here suggests the search query is being built with string concatenation rather than parameterized inputs, even through an ORM layer.

---

## Real Breaches This Maps To

**Heartland Payment Systems, 2008** - SQL injection against a payment processor. 130 million credit card numbers stolen. At the time, one of the largest data breaches ever recorded.

**Sony Pictures, 2011** - SQL injection exposed personal data of over 1 million users. The attackers publicly stated the method was trivially simple and the data was stored in plaintext.

**Freepik, 2020** - SQL injection against a popular design asset site exposed 8.3 million user records including emails and hashed passwords. MD5 hashes without salting - same storage mistake as Juice Shop - meant a significant portion were immediately crackable.

**Cisco, 2023** - SQL injection vulnerabilities were found in Cisco's Unified Communications Manager. Authenticated attackers could execute arbitrary SQL commands. Even enterprise-grade software ships with injection bugs regularly.

---

## Remediation

| Issue | Fix |
|---|---|
| SQL injection in login | Use parameterized queries or prepared statements - never concatenate user input into SQL |
| SQL injection in search | Same - parameterized queries; ORM methods that enforce binding, not raw string queries |
| MD5 password hashing | Use bcrypt, scrypt, or Argon2 with per-user salts; MD5 is not a password hashing algorithm |
| HTML injection in search output | Encode all user-supplied output before rendering; use `textContent` instead of `innerHTML` in JavaScript |
| No input validation | Validate and reject inputs that don't match expected patterns before they reach the query layer |

---

## Three Takeaways

Six characters bypassed authentication. `' OR 1=1--` is one of the oldest known SQL injection payloads. It's been public knowledge since the late 1990s. The fact that it still works against modern applications is not a technical problem - it's a code review problem.

The UNION response mapped the entire schema. When the column enumeration returned field names like `id`, `name`, `description`, `price`, I knew exactly what the underlying `Products` table looked like. That's free intelligence for targeting the next query. Injection vulnerabilities don't just give access - they give a roadmap.

HTML injection and XSS are the same bug at different severity levels. The `<h1>` rendered because the app put user input directly into the DOM. Whether that becomes a phishing overlay or a full XSS payload depends only on what tags and attributes the app filters - and if it's not filtering `<h1>`, it probably isn't filtering `<script>` either.

---

> **Lab:** OWASP Juice Shop (TryHackMe instance, 10.49.132.55) | **Tools:** Burp Suite Community, Browser DevTools, CrackStation | **Category:** OWASP A03:2021 - Injection
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
