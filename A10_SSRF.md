# OWASP Top 10 Labs Series - SSRF: Two Labs, Two Ways a Server Fetches What It Shouldn't

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. SSRF falls under A10:2021 (Server-Side Request Forgery). This entry covers two PortSwigger labs - one basic, one with a blacklist filter to bypass. Follow along for the full A01 through A10 series.

---

## The Bug - What Is SSRF?

Server-Side Request Forgery is when an attacker makes the server send HTTP requests on their behalf. The application has a feature that fetches a URL - and that URL is user-controlled. Instead of pointing it at the intended destination, you point it at something internal. The server makes the request from its own network, with its own trust level, and returns whatever it gets back.

The impact is significant because internal services often have zero authentication. They trust requests from localhost or the internal network implicitly. From the outside you'd be blocked. But if you can make the server ask on your behalf, you're inside.

---

## Lab 1 - Basic SSRF Against the Local Server

**Platform:** PortSwigger Web Security Academy

### Finding the Attack Surface

Opened a product page and clicked **Check stock**. Burp Intercept caught the request before it left the browser.

**[SS1 - Burp Intercept: POST /product/stock intercepted, request body shows stockApi parameter set to the encoded stock checker URL at stock.weliketoshop.net:8080]**
<img width="1630" height="767" alt="Screenshot 2026-07-10 005515" src="https://github.com/user-attachments/assets/70fa72be-1d11-4e2b-9d04-7e3bd7c10c68" />



The `stockApi` parameter contained a full URL the server would fetch server-side:

```
stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck...
```

User-controlled URL passed to a server-side fetch. That's the entry point. Sent it to Repeater.

### Redirecting the Server to Localhost

Changed `stockApi` to:

```
stockApi=http://localhost/admin
```

**[SS2 - Repeater with changed stockApi URL to localhost/admin]**
<img width="721" height="527" alt="Screenshot 2026-07-10 010111" src="https://github.com/user-attachments/assets/1d20a743-014e-4c57-a7fe-707bdd0cf803" />



The server fetched `http://localhost/admin` from its own loopback interface and returned the HTML response directly. The admin panel - which would have blocked an external visitor - was wide open to requests coming from localhost. I was reading internal admin HTML through a stock check endpoint.

### Reading the Admin Panel Response

Scrolled through the returned HTML.

**[SS3a - Burp Repeater: POST /product/stock with stockApi=http://localhost/admin, response is HTTP/2 200 OK returning full admin page HTML including the title "Basic SSRF against the local server"]**
<img width="1807" height="720" alt="Screenshot 2026-07-10 005935" src="https://github.com/user-attachments/assets/bfddddd4-d3a9-40f0-a773-0762c3c6320a" />


**[SS3b - Response HTML showing Users section: wiener and carlos listed with delete links /admin/delete?username=wiener and /admin/delete?username=carlos]**
<img width="1068" height="557" alt="Screenshot 2026-07-10 010229" src="https://github.com/user-attachments/assets/81520224-b57c-418e-a35d-25c1edcc3970" />


The response included the full admin panel markup - user list, navigation links, and the delete endpoints. The application handed me the internal API structure through its own response.

### Executing the Delete via SSRF

Modified `stockApi` to target the delete endpoint directly:

```
stockApi=http://localhost/admin/delete?username=carlos
```

**[SS4 - Burp Repeater: stockApi=http://localhost/admin/delete?username=carlos, response is HTTP/2 302 Found redirecting to /admin]**
<img width="1725" height="670" alt="Screenshot 2026-07-10 010442" src="https://github.com/user-attachments/assets/01544154-cb2e-4f29-b1f4-8b7edadcdc6b" />


`302 Found`. The server executed the delete action - not me, but the server itself acting on my behalf against its own internal admin endpoint.

**[SS5 - Browser: PortSwigger lab page "Basic SSRF against the local server" - LAB Solved banner, page text reads "Admin interface only available if logged in as an administrator, or if requested from loopback"]**
<img width="1758" height="527" alt="Screenshot 2026-07-10 010521" src="https://github.com/user-attachments/assets/781c9a8c-852c-477a-b964-3254f398f348" />



Lab solved. The message on the page makes the vulnerability design explicit: the admin panel trusts loopback requests. SSRF weaponizes that trust assumption.

---

## Lab 2 - SSRF With Blacklist-Based Input Filter

**Platform:** PortSwigger Web Security Academy

The second lab adds a server-side filter that's supposed to block SSRF. The approach shifts from straightforward exploitation to filter analysis and bypass.

### Hitting the Blacklist

Same setup - intercepted the stock check, sent to Repeater, replaced `stockApi` with `http://localhost/admin`.

**[SS6 - Burp Repeater: stockApi=http://localhost/admin, response is HTTP/2 400 Bad Request, body reads "External stock check blocked for security reasons"]**
<img width="1847" height="502" alt="Screenshot 2026-07-10 011118" src="https://github.com/user-attachments/assets/a6059b09-deb5-4489-9960-048892a46625" />



Blocked. The filter detected `localhost` in the URL and rejected it. Now the question was: what exactly is the filter checking, and can I represent the same address in a way it doesn't recognize?

### Finding What Gets Through

Tested alternate representations of `127.0.0.1`:

- `http://127.1/` returned **200 OK** - the shortened IP bypassed the localhost check
- `http://127.1/admin` was still blocked - so the filter also matched the word `admin` in the path

Two things on the blacklist: the string `localhost` and the string `admin`. Both needed bypassing independently.

### The Double Encoding Bypass

The path filter checks for `admin` literally. But what if `admin` isn't written as `admin` when the filter reads it?

URL encoding turns `a` into `%61`, making `admin` become `%61dmin`. Submit `%2561dmin` - where `%25` is the encoded form of `%` - and the filter sees `%61dmin` (not `admin`), passes it, and the server decodes it a second time to `admin` before making the request.

Payload:

```
stockApi=http://127.1/%2561dmin
```

**[SS7 - Burp Repeater: stockApi=http://127.1/%2561dmin, response shows full admin panel HTML with Users section - wiener and carlos listed with /admin/delete?username=carlos delete link visible]**
<img width="1852" height="701" alt="Screenshot 2026-07-10 011638" src="https://github.com/user-attachments/assets/586bab94-db2f-4833-9686-06d7d456a644" />



Admin panel returned. `127.1` bypassed the localhost check, `%2561dmin` bypassed the path check. The server decoded the double-encoded path and fetched the internal admin page.

### Deleting the User Through the Bypass

Applied the same encoding to the delete endpoint:

```
stockApi=http://127.1/%2561dmin/delete?username=carlos
```

**[SS8 - Burp Repeater: stockApi=http://127.1/%2561dmin/delete?username=carlos, response is HTTP/2 302 Found with Location: /admin]**
<img width="1817" height="472" alt="Screenshot 2026-07-10 011713" src="https://github.com/user-attachments/assets/a41b187c-8407-4527-90e9-9b03423522b0" />



`302 Found`. Delete executed through the bypass payload.

**[SS9 - Browser: PortSwigger lab page "SSRF with blacklist-based input filter" - LAB Solved banner, page reads "Admin interface only available if logged in as an administrator, or if requested from loopback"]**
<img width="1897" height="480" alt="Screenshot 2026-07-10 011741" src="https://github.com/user-attachments/assets/8761758e-aa42-413b-b6d4-b25d5194ba7b" />



Both labs solved. The blacklist provided a speed bump, not protection.

---

## The Full Attack Chains

**Lab 1:** Intercept stock check → identify user-controlled `stockApi` URL → replace with `http://localhost/admin` → server fetches internal admin page → read HTML for delete endpoints → send `http://localhost/admin/delete?username=carlos` → 302 confirms deletion → lab solved.

**Lab 2:** Same starting point → `http://localhost/admin` blocked → test alternate IP representations → `http://127.1/` passes → `/admin` path blocked → double URL-encode the path (`%2561dmin`) → `http://127.1/%2561dmin` returns admin HTML → apply same encoding to delete endpoint → 302 confirms deletion → lab solved.

---

## What I Didn't Test But Exists

**AWS Metadata Service (IMDS) via SSRF**

The most impactful real-world SSRF target is `http://169.254.169.254/latest/meta-data/`. On AWS EC2 instances, this endpoint returns IAM credentials, instance metadata, and security tokens - all unauthenticated, accessible only from the instance itself. An SSRF vulnerability in an application running on EC2 hands an attacker the cloud credentials for the underlying instance. This is exactly how the Capital One breach worked in 2019.

**Internal Network Port Scanning**

With a controllable `stockApi` parameter you can point it at internal IP ranges and observe response times and status codes. A `200` means the port is open, a connection refused or timeout means it isn't. This turns SSRF into an internal network scanner - you can map what services are running internally without ever touching the network directly.

**Protocol Smuggling**

SSRF isn't limited to HTTP. Depending on the fetch library, you can sometimes use other schemes: `file:///etc/passwd` to read local files, `gopher://` to send raw TCP data to internal services, or `dict://` to interact with dictionary servers. These expand SSRF from internal HTTP access to arbitrary internal communication.

**Whitelist Bypass via Open Redirect**

Some SSRF filters use allowlists - only specific domains permitted. If any page on the allowed domain has an open redirect, you can chain them: point `stockApi` at the allowed domain's redirect endpoint, which forwards to an internal IP. The filter sees an approved domain, the server follows the redirect, and you land at the internal target.

**Blind SSRF**

In blind SSRF the server makes the request but doesn't return the response. Detection relies on out-of-band channels - Burp Collaborator or a webhook to confirm the server made an outbound request to your controlled domain. Even without reading the response, blind SSRF confirms the vulnerability and can be used for internal port scanning via timing side-channels.

---

## Real Breaches This Maps To

**Capital One, 2019** - A misconfigured WAF combined with SSRF allowed an attacker to hit the AWS metadata endpoint at `169.254.169.254` and retrieve IAM role credentials. Those credentials were used to access over 100 million customer records in S3. SSRF to cloud credential theft to mass data exfiltration, all through one parameter.

**GitLab, 2021** - CVE-2021-22214 was an SSRF vulnerability in GitLab's Prometheus integration. An unauthenticated attacker could make the GitLab server send requests to internal services, exposing internal infrastructure details.

**Shopify, 2015** - An SSRF bug in Shopify's image import feature allowed scanning internal network services by supplying internal IPs as image URLs. The server would attempt to fetch the image and error responses revealed open ports.

---

## Remediation

| Issue | Fix |
|---|---|
| User-controlled URL in server-side fetch | Allowlist specific permitted destinations only - no arbitrary URLs |
| Blacklist-based filtering | Blacklists are bypassable by design; switch to strict allowlists |
| Alternate IP representations not blocked | Resolve all URLs to IP before comparing; block all RFC 1918 ranges and loopback at resolution time |
| Path string matching for "admin" | Fully normalize and decode URLs before any filtering check - all encoding passes |
| Cloud metadata endpoint accessible | Enable IMDSv2 on AWS (requires token-based requests, blocks simple SSRF); restrict metadata at the network level |

---

## Three Takeaways

The stock check feature had no reason to accept arbitrary URLs. It should only accept requests to its own known stock service. The moment user input controls the destination of a server-side fetch, SSRF is possible. Functionality scope matters as much as input validation.

Blacklists fail the moment you think of a representation the developer didn't. `localhost`, `127.0.0.1`, `127.1`, `2130706433`, `0177.0.0.1`, `::1` - all resolve to loopback. A blacklist has to enumerate every representation. An allowlist only defines what's permitted. One approach scales, the other doesn't.

The double encoding bypass is the most transferable lesson from Lab 2. `%2561dmin` works because the filter decodes once and the server decodes again. Anytime a security control checks a value before the application processes it, there's a potential mismatch in how many decode passes each side performs. That gap is a bypass.

---

> **Lab:** PortSwigger Web Security Academy - SSRF Labs | **Tools:** Burp Suite Community, Browser DevTools | **Category:** OWASP A10:2021 - Server-Side Request Forgery (SSRF)
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
