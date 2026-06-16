# OWASP Top 10 Labs Series #6 - A06: Vulnerable and Outdated Components

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. This is entry #6. Follow along for A01 through A10.

<img width="728" height="420" alt="owasp" src="https://github.com/user-attachments/assets/bd7b05bf-2173-42e8-afa8-a78cedf3d5b3" />

---

## The Bug - What Is A06 Vulnerable and Outdated Components?

Your application is only as secure as the oldest library it depends on.

A06 is about third-party packages that have known CVEs published against them but the app is still running the old version. The attacker doesn't find a new bug - someone already found it, published it on NVD, and the app just never updated. No custom exploit needed. Just version numbers and a public database.

---

## Recon - Passive Fingerprinting First

Started with Burp Suite, intercepted the initial `GET /` and checked response headers for any version leaks.

**[SS1 - Burp Suite HTTP History: GET / returning 200 OK, response headers visible - security headers present, no X-Powered-By]**

<img width="1902" height="912" alt="Screenshot 2026-06-16 144227" src="https://github.com/user-attachments/assets/bf578b3a-fe6c-42f9-a0cc-5c6be2798052" />


No `X-Powered-By` header. The app wasn't advertising its stack directly. Most apps suppress obvious version headers now - the real disclosure happens elsewhere. I already knew where from the A05 lab.

---

## Getting the Dependency File - Null-Byte Bypass

In the A05 assessment, I found `package.json.bak` in the exposed `/ftp` directory but the server blocked `.bak` access with a 403. This time I came back with a bypass.

The extension filter only checked the string after the last dot. Appending `%2500.md` - a null-byte encoded as `%25` followed by `00` - tricks the check into reading the filename as ending in `.md`, while the actual file served is still the `.bak`.

Payload: `http://10.48.145.249/ftp/package.json.bak%2500.md`

**[SS2 - Browser showing /ftp/package.json.bak%2500.md: 403 error page in background, download popup showing package.json.bak_00.md downloaded at 4.2 KB]**

<img width="1787" height="563" alt="Screenshot 2026-06-16 144745" src="https://github.com/user-attachments/assets/b58915ec-1e6e-41fa-aaf0-e621aa92114b" />


Error page rendered, file downloaded anyway. The filter was bypassed and I had the full dependency manifest locally. This is also why the A05 misconfiguration matters beyond just the confidential document - it enabled this entire A06 chain.

---

## Reading the Manifest

Opened the downloaded file in VS Code.

**[SS3 - VS Code showing package.json contents: name "juice-shop", version "6.2.0-SNAPSHOT", contributors list visible]**

<img width="1325" height="945" alt="Screenshot 2026-06-16 144934" src="https://github.com/user-attachments/assets/b2a117bb-aaf2-497c-9e35-c1113839ce74" />



Version `6.2.0-SNAPSHOT`. An old snapshot build. Already a signal this isn't a regularly patched codebase. I scrolled to the `dependencies` section.

---

## Finding 1: The Dependency List Is a CVE Shopping List

**[SS4 - VS Code showing dependencies: express "~4.16", express-jwt "0.1.3", js-yaml "3.10", jsonwebtoken "~8", sanitize-html visible alongside body-parser, cors, sequelize]**

<img width="713" height="958" alt="Screenshot 2026-06-16 145148" src="https://github.com/user-attachments/assets/44818741-8590-4bf3-9e7e-884bf4320260" />


A few entries stood out immediately:

- `sanitize-html` - a library specifically meant to prevent XSS. Version looked old.
- `js-yaml 3.10` - YAML parser, known prototype pollution issues in this range
- `express-jwt 0.1.3` - ancient JWT middleware
- `jsonwebtoken ~8` - version 8.x has documented algorithm confusion issues

With exact versions in hand, I went to NVD.

---

## Finding 2: sanitize-html 1.4.2 - CVE-2016-1000237

**[SS5 - NVD search for "sanitize-html 1.4" returning CVE-2016-1000237, published 2020-01-23, description: "sanitize-html before 1.4.3 has XSS"]**

<img width="1910" height="887" alt="Screenshot 2026-06-16 145617" src="https://github.com/user-attachments/assets/3eab623a-0ffa-4b99-a9f6-1191791f41ea" />


**[SS6 - NVD CVE detail for CVE-2016-1000237: CVSS 3.x Base Score 6.1 MEDIUM, vector AV:N/AC:L/PR:N/UI:R]**

<img width="1907" height="877" alt="Screenshot 2026-06-16 145747" src="https://github.com/user-attachments/assets/3639fae7-802f-46d0-b7cd-793200e33f72" />


`sanitize-html` is supposed to strip dangerous HTML and prevent XSS. Version 1.4.2 has a bypass for exactly that protection - crafted input survives sanitization and executes in the browser. The library meant to prevent XSS is itself the XSS vector. The app uses this in review and feedback functionality, meaning anywhere user input renders back as HTML is potentially exploitable.

---

## Finding 3: js-yaml 3.10 - CVE-2025-64718

**[SS7 - NVD CVE detail for CVE-2025-64718: js-yaml before 4.1.1 and 3.14.2 allows prototype pollution via __proto__ in parsed YAML, Base Score 5.3 MEDIUM, CNA GitHub Inc.]**

<img width="1918" height="868" alt="Screenshot 2026-06-16 150010" src="https://github.com/user-attachments/assets/024ee895-6039-4013-993a-4d2067bc98e5" />


Version `3.10` falls below the patched threshold of `3.14.2`. The vulnerability allows an attacker to pollute `Object.prototype` by passing a crafted YAML document with `__proto__` keys. Prototype pollution has been used in real attacks to bypass authentication checks, escalate privileges, and trigger RCE in downstream code that trusts polluted properties. The CVE was published November 2025 - after the app was built. That's exactly how A06 plays out in production: you ship something clean and the CVEs catch up.

---

## Finding 4: Retire.js Scan - jQuery 2.2.4, Five Vulnerabilities

The `package.json` covers server-side dependencies. For client-side I ran a Retire.js scan against the running app to see what's actually being delivered to the browser.

**[SS8 - Retire.js report showing jQuery 2.2.4 flagged as "at risk", listing CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023, with "jQuery 1.x and 2.x are End-of-Life" note]**

<img width="856" height="720" alt="image" src="https://github.com/user-attachments/assets/89e33abf-e167-45d1-8f8b-c316a078d635" />


Retire.js flagged jQuery 2.2.4 loaded from Cloudflare CDN with five documented issues:

- **CVE-2015-9251** - 3rd party CORS request may execute
- **CVE-2019-11358** - Prototype pollution via `jQuery.extend`
- **CVE-2020-11022** - XSS via `jQuery.htmlPrefilter` regex
- **CVE-2020-11023** - XSS via `<option>` elements in DOM manipulation methods
- **jQuery 1.x and 2.x are End-of-Life** - no longer receiving security updates

Five findings from a single library version number. And it's not just listed as a dependency - it's actively loaded.

---

## Finding 5: Runtime Confirmation - jQuery Live in Every Browser

**[SS9 - Browser DevTools Network tab: jquery.min.js fetched from cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js, status 200, 85.58 kB cached]**

<img width="1918" height="905" alt="Screenshot 2026-06-16 150453" src="https://github.com/user-attachments/assets/d32a1031-99f8-48d2-870c-90780bdc08f5" />


Network tab confirms `jquery.min.js` version 2.2.4 is fetched with a 200 response on every page load. This matters because a dependency in `package.json` might be installed but unused. This one is running in every user's browser, right now.

---

## The Full Attack Chain

Passive header recon → no version leak → recall exposed `/ftp` from A05 → null-byte bypass downloads `package.json.bak` → read exact dependency versions → NVD search maps `sanitize-html 1.4.2` to XSS bypass CVE → `js-yaml 3.10` to prototype pollution CVE → Retire.js scan catches client-side jQuery 2.2.4 with five CVEs → DevTools confirms it's live → full vulnerability map documented.

No exploit written. NVD and Retire.js did the work. The app just never updated.

---

## What I Didn't Test But Exists

**express-jwt 0.1.3 - Algorithm Confusion**

This version predates fixes for JWT `alg: none` attacks. If the library accepts a token with the algorithm field stripped out, an attacker can forge valid tokens without a signature. Worth testing by sending a JWT with `"alg": "none"` and an empty signature and observing whether the app accepts it.

**jsonwebtoken ~8 - RS256/HS256 Key Confusion**

Version 8.x has documented issues with algorithm confusion between RS256 and HS256. An attacker who gets hold of the server's public key can use it as an HMAC secret to forge tokens the server will verify as valid. This is the kind of vulnerability that turns a read-only information disclosure into a full authentication bypass.

**Sequelize 4.x - Raw Query Injection**

Older Sequelize versions are looser about parameterizing raw queries. If the app constructs any raw SQL with user input, this version is a candidate for SQL injection. Modern Sequelize enforces parameterization much more strictly.

**Transitive Dependencies**

I only looked at direct dependencies here. Every package in `package.json` has its own dependencies, and those have more. The actual vulnerable surface is much larger than what's visible in this file. `npm audit` scans the full tree and would return significantly more findings than what I found manually.

**Automated SCA**

The real fix for A06 isn't manual NVD searches - it's Software Composition Analysis baked into CI/CD. Tools like `npm audit`, Snyk, or OWASP Dependency-Check flag these before deployment and can block merges on critical CVEs. Running `npm audit` against this manifest right now would return a wall of findings.

---

## Real Breaches This Maps To

**Equifax, 2017** - Apache Struts CVE-2017-5638 had a patch available for months. It wasn't applied. 147 million people's data exposed. The most cited A06 breach for a reason.

**Log4Shell, 2021** - CVE-2021-44228 in Log4j hit virtually every Java application. The library was used everywhere, often without teams even knowing. Orgs scrambled because nobody had a clear inventory of where Log4j was running.

**event-stream, 2018** - Malicious code was injected into a widely-used npm package. Applications running the compromised version executed attacker code. A06 from the supply chain angle - not just outdated, but actively compromised.

---

## Remediation

| Component | Issue | Fix |
|---|---|---|
| `sanitize-html 1.4.2` | XSS bypass (CVE-2016-1000237) | Update to 1.4.3 or latest |
| `js-yaml 3.10` | Prototype pollution (CVE-2025-64718) | Update to 3.14.2 minimum or 4.x |
| `jQuery 2.2.4` | Five CVEs, End-of-Life | Upgrade to jQuery 3.7+ |
| `express-jwt 0.1.3` | Algorithm confusion risk | Upgrade; enforce algorithm allowlist |
| Null-byte bypass | Extension filter bypass | Validate actual file type, not just the extension string |
| No automated scanning | CVEs go undetected | Add `npm audit` or Snyk to CI/CD pipeline |

---

## Three Takeaways

Version numbers are attacker intelligence. The moment a dependency manifest is readable by an unauthenticated user, every version in it becomes a recon artifact. I didn't find a vulnerability - I read a file, opened NVD, and had a CVE map in 20 minutes.

The null-byte bypass connected A05 directly to A06. A properly locked-down file server never exposes the manifest in the first place. These categories don't exist in isolation - one misconfiguration kept opening doors for the next finding.

End-of-life libraries in production are a slow timer. jQuery 2.2.4 has been EOL for years and carries five documented CVEs. An attacker doesn't need to discover anything - the research is already done and published. That's why Equifax happened. Patching isn't exciting work but skipping it is what makes breaches like that possible.

---

> **Lab:** OWASP Juice Shop (hosted instance, 10.48.145.249) | **Tools:** Burp Suite Community, Browser DevTools, Retire.js, NVD (nvd.nist.gov) | **Category:** OWASP A06:2021 - Vulnerable and Outdated Components
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
