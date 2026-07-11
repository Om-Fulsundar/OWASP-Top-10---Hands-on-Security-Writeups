# OWASP Top 10 Labs Series #4 - A04: Insecure Design

> **Series:** I'm working through all ten OWASP Top 10 vulnerability categories hands-on using Juice Shop and PortSwigger, and documenting each one. This is entry #4. Follow along for A01 through A10.

---

## The Bug - What Is A04 Insecure Design?

A04 is different from most vulnerability categories. It's not about a misconfigured setting or a missing input sanitization check - those are implementation failures. Insecure design is about the application's logic being fundamentally wrong from the start. The feature was built without asking "what happens if someone abuses this?"

Business logic flaws are the most common form. The application accepts input it was never supposed to. It trusts data from the client that should only ever come from the server. It performs operations without asking whether they make sense in the real world - like allowing negative quantities in a shopping cart, or letting a buyer set the price of their own purchase.

This lab covers two distinct cases: a business rule validation failure in Juice Shop where negative quantities are accepted server-side, and a PortSwigger lab where the server trusts client-supplied pricing data during checkout.

---

## Bug 1 - Negative Quantity Accepted (Juice Shop)

**Target:** OWASP Juice Shop (TryHackMe)

### Finding the Request

Added a product to the basket and watched Burp HTTP History for the quantity update request. When you change a quantity in the basket UI, Juice Shop fires:

```
PUT /api/BasketItems/{id}
```

with a JSON body containing the new quantity. Sent it to Repeater.

### Sending quantity: -1

Changed the quantity to `-1` and sent the request.

**[SS1 - Burp Repeater: PUT /api/BasketItems/10 with request body "quantity":-1, response 200 OK, response body showing status:success, data object confirming ProductId:24, BasketId:1, id:10, quantity:-1]**
<img width="1462" height="681" alt="Screenshot 2026-07-11 144657" src="https://github.com/user-attachments/assets/5b1a4154-38ad-4923-808f-4eb6188d9469" />



`200 OK`. The server accepted `-1` as a valid quantity and stored it. The response body confirms it - `"quantity": -1` written back to the database. No validation, no rejection, no error.

### Basket State After Manipulation

Refreshed the browser basket.

**[SS2 - Browser: Juice Shop basket showing Apple Juice (1000ml) quantity 1 at 1.99¤, Apple Pomace with quantity showing -1 at 0.89¤, Total Price: 1.1¤ - the negative item is reducing the total]**
<img width="1918" height="858" alt="Screenshot 2026-07-11 144755" src="https://github.com/user-attachments/assets/83b945f2-c2c5-41a5-b81c-4a7f4f189909" />


The basket rendered the `-1` quantity for Apple Pomace and the total price dropped accordingly. Apple Juice at 1.99 minus Apple Pomace at 0.89 gave a total of 1.1¤ instead of 2.88¤. The negative quantity item is actively subtracting from the order total.

In a real e-commerce system this could be used to offset the cost of other items, achieve near-zero order totals, or in some implementations trigger credit to the attacker's account.

### Pushing It Further - quantity: -100

Changed the quantity to `-100` and sent again.

**[SS3 - Burp Repeater: PUT /api/BasketItems/10 with "quantity":-100, response 200 OK, response body confirming quantity:-100 stored successfully]**
<img width="1717" height="677" alt="Screenshot 2026-07-11 144844" src="https://github.com/user-attachments/assets/003a8e71-ee03-4aad-b963-adc9582bffe0" />



Still `200 OK`. `quantity: -100` accepted and stored without complaint. There's no floor, no ceiling, no server-side boundary check of any kind. The API will accept any integer the client sends.

This is the definition of insecure design - the business rule "quantity must be a positive integer" was simply never implemented on the server. The UI probably prevents typing `-1` into the field, which is the extent of the validation. Bypass the UI with Burp and the entire rule disappears.

---

## Bug 2 - Excessive Trust in Client-Side Controls (PortSwigger)

**Target:** PortSwigger Web Security Academy - "Excessive trust in client-side controls"

### Finding the Price Parameter

Added the Lightweight "l33t" Leather Jacket to the cart and intercepted the POST request with Burp.

**[SS4 - Burp Intercept: POST /cart intercepted, request body showing productId=1&redir=PRODUCT&quantity=1&price=133700 - the price parameter visible in the form data, original price 133700 cents ($1337.00)]**
<img width="1391" height="808" alt="Screenshot 2026-07-11 151547" src="https://github.com/user-attachments/assets/d9b461a2-9fdd-4f38-a04b-fab31d47cbf1" />



The request body contained:

```
productId=1&redir=PRODUCT&quantity=1&price=133700
```

The `price` field is there. In the form data. Sent by the client. The jacket costs `$1337.00` - the price is `133700` in cents - and that value is being submitted by the browser as part of the add-to-cart request. The server is expected to trust whatever number the client sends.

This should never happen. Pricing is authoritative server-side data. It belongs in the database, looked up by product ID, verified at checkout. Sending it from the client is the same as letting a customer write their own price tag at the checkout counter.

### Changing the Price

Sent to Repeater. Changed `price=133700` to `price=1`.

**[SS5 - Burp Repeater: POST /cart with price=1 in the request body, response 302 Found redirecting to /product?productId=1 - server accepted the manipulated price without error]**
<img width="1455" height="646" alt="Screenshot 2026-07-11 151650" src="https://github.com/user-attachments/assets/6a06643c-2907-4f12-971d-e4875527dc03" />



`302 Found`. The server processed the add-to-cart with `price=1` (one cent) and redirected back to the product page. No error. No validation. No comparison against the actual product price in the database.

### Order Confirmed at $0.02

Proceeded through checkout in the browser.

**[SS6 - Browser: PortSwigger lab page "Excessive trust in client-side controls" - LAB Solved banner, order confirmation showing Lightweight "l33t" Leather Jacket, Price $1337.00, Quantity 2, Total: $0.02, Store credit: $99.98]**
<img width="1913" height="651" alt="Screenshot 2026-07-11 151727" src="https://github.com/user-attachments/assets/53b2cb60-6d01-4c3d-8784-7acdf9d7c384" />



Two jackets at $1337.00 each - total should be $2674.00. The order processed for $0.02. Lab solved.

The `$1337.00` shown next to each item is the display price pulled from the product catalog. The actual amount charged was whatever the client submitted in the `price` parameter - one cent per item, two cents total.

---

## The Full Attack Chains

**Bug 1:** Add item to basket → capture PUT /api/BasketItems/{id} in Burp → send to Repeater → change quantity to -1 → 200 OK, stored in database → basket total reduced → repeat with -100 → no boundary enforcement at any value.

**Bug 2:** Add product to cart → intercept POST /cart → identify `price` parameter in client-supplied form data → send to Repeater → change price from 133700 to 1 → 302 confirms accepted → checkout → order confirmed at $0.02 for two $1337 jackets.

---

## What I Didn't Test But Exists

**Coupon Code Stacking and Replay**

Business logic flaws extend to discount systems. Applications sometimes allow applying the same coupon multiple times in the same session, stacking multiple coupons that weren't designed to combine, or replaying expired coupon codes. These are design failures - the intended business rule was "one coupon per order" but the enforcement was never implemented. Juice Shop has specific coupon challenges that follow this exact pattern.

**Race Conditions on Limited Resources**

Some business logic depends on state that changes over time - limited stock, one-per-customer promotions, loyalty point redemptions. If the server checks availability and completes the transaction in two separate operations, sending multiple simultaneous requests can race through the check before the state updates. Two threads both see "1 item left in stock", both pass the check, both complete the purchase. The design assumed serial execution, reality is concurrent.

**Quantity Overflow**

Taking the negative quantity logic further: what happens at extremely large positive values? Some systems use 32-bit signed integers for quantities, meaning a value above 2,147,483,647 wraps around to negative. If the pricing calculation uses the quantity directly in a multiplication, an overflowed quantity could produce a negative total - same financial impact as the negative quantity bug but triggered differently.

**Free Checkout via Logic Manipulation**

Combining the two bugs: negative quantity on one item reduces the total, positive quantity on another increases it. If the checkout system sums all items and the total can reach zero or negative, it might process for free or generate a refund. The design assumed prices would always produce a positive total. Business logic that makes mathematical assumptions about user input without enforcing them is inherently fragile.

**Parameter Tampering Beyond Price**

In the PortSwigger lab the price was tampered. The same principle applies to any server-trusted client parameter: shipping cost, tax rate, discount percentage, loyalty point redemption value. Any numeric value the server reads from the request rather than computing from its own data is a potential manipulation target. A complete assessment would identify every parameter in the checkout flow and test each one for server-side validation.

---

## Real Breaches This Maps To

**Starbucks, 2015** - A researcher discovered that Starbucks gift card transfers had a race condition allowing the same balance to be transferred multiple times simultaneously. By sending multiple concurrent transfer requests before the balance updated, funds could be duplicated. Business logic design assumed transactions would execute serially.

**airlines.com / Booking Price Manipulation, recurring** - Multiple airline and travel booking sites have been found to trust client-supplied prices in form parameters, allowing attackers to book flights for near-zero fares. The attack is structurally identical to Bug 2 - the price shown to the user gets echoed back in the form submission and the server uses that value rather than looking up the authoritative price.

**Magecart Attacks, 2018-present** - While Magecart is primarily a card skimming attack, its prevalence is enabled partly by insecure design - checkout flows that process payment without server-side price verification. An attacker who can modify the cart total client-side before card processing can charge cards for arbitrary amounts.

---

## Remediation

| Issue | Fix |
|---|---|
| Negative quantity accepted server-side | Enforce `quantity >= 1` validation on the server before processing any basket update; reject and return 400 for any value outside the permitted range |
| No upper boundary on quantity | Set a sensible maximum quantity per item server-side; flag unusually large values for review |
| Client-supplied price trusted at checkout | Never accept price from the client; always look up the authoritative price from the product database server-side using the productId; the client sends what to buy, not what to pay |
| No business rule enforcement at API layer | Business rules must live on the server, not the UI; frontend validation is UX, not security; every constraint must be re-enforced when the raw request reaches the API |

---

## Three Takeaways

Frontend validation is not security. The Juice Shop UI almost certainly prevents typing `-1` into the quantity field. That protection disappears the moment someone opens Burp and edits the raw request. Every business rule enforced only in JavaScript is effectively not enforced at all from a security standpoint.

The client tells the server what to buy, never what to pay. The PortSwigger bug exists because a developer passed the displayed price back in the form data and the server used it. Authoritative data - price, tax, shipping, discount - belongs in the database and should be computed server-side from the product ID alone. Anything the client sends about pricing should be ignored.

Insecure design is the hardest category to patch after the fact. You can add input validation to fix injection. You can update a library to fix A06. But a checkout flow that fundamentally trusts client-supplied pricing requires rethinking the data flow, which touches the frontend, the API contract, and the backend logic simultaneously. This is why it's a design problem, not an implementation one - catching it at code review is exponentially cheaper than retrofitting it after deployment.

---

> **Lab:** OWASP Juice Shop (TryHackMe, 10.48.176.58) + PortSwigger Web Security Academy | **Tools:** Burp Suite Professional, Browser | **Category:** OWASP A04:2021 - Insecure Design
>
> *Part of my OWASP Top 10 Labs Series - documenting all ten categories hands-on. More writeups coming.*
