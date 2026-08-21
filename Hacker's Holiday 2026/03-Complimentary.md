Complimentary - TryHackMe Hacker's Holiday 2026
================================================================

**Room:** [Complimentary (TryHackMe Hacker's Holiday 2026)](https://tryhackme.com/room/hh-complimentary-05e0b604?vccr=1)

**Category:** Cloud - AWS Cognito / IAM Misconfiguration

**Vulnerability class:** Overly Permissive IAM Role Attached to Unauthenticated Cognito Identity Pool - related to [OWASP API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) and AWS's own guidance against granting broad table access to unauth identity pool roles.

<img width="1908" height="510" alt="Screenshot 2026-08-21 200301" src="https://github.com/user-attachments/assets/8619ed65-2c39-4b03-b884-2c49eee8b143" />


## Scenario

The Byte Lotus Wellness app is the hotel's free companion app — no account, no login screen, just open it and it already has a name and notes waiting for you. Lambo installed it on day one, gave it the permissions it asked for, and got a tote bag for her trouble. The briefing's whole point is that "no login" doesn't mean "no credentials" — something is quietly issuing AWS access behind the scenes, and whatever it is, it isn't being careful about what it hands out. The goal was to find that mechanism, get its credentials, and see how much of the app's backend data those credentials actually reach.

## First contact

I opened the target site and got a plain, generic welcome screen:

> Byte Lotus Wellness — Your free wellness dashboard
>
> No account needed — we set you up as a guest the moment you arrived.
>
> Welcome! We don't have wellness data for you yet — check back after your first spa visit.

Nothing personalized yet, no login prompt, just a page that clearly expects to know things about visitors eventually. That "eventually" was the interesting part — something on the backend was going to start recognizing me.

## The actual move: read the client-side JS, then take its credentials for a walk

I inspected the page source and found `app.js`, which laid out the entire architecture in the comments:

```javascript
const IDENTITY_POOL_ID = "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688";
const AWS_REGION = "us-east-1";
const TABLE_NAME = "complimentary-GuestWellnessProfiles";

AWS.config.credentials = new AWS.CognitoIdentityCredentials({
  IdentityPoolId: IDENTITY_POOL_ID,
});
```

So the app hands every visitor real, temporary AWS credentials from a Cognito Identity Pool with unauthenticated access enabled — no login required by design. The rest of `app.js` used those credentials to run a scoped `dynamodb.getItem()` against a table called `complimentary-GuestWellnessProfiles`, keyed to a random `guest-xxxxxxxx` ID stored in `localStorage`. In other words: the *app* only ever asked for your own record. Nothing said the *credentials* were limited to that.

I didn't have the AWS CLI installed, so instead of running commands locally I used the browser's own DevTools console — since `app.js` already loads the AWS SDK on the page, I could just reuse it live. First, I forced the credential fetch and printed it:

```javascript
AWS.config.credentials.get(function(err) {
  if (err) { console.error("Cred error:", err); return; }
  console.log("AccessKeyId:", AWS.config.credentials.accessKeyId);
  console.log("SecretAccessKey:", AWS.config.credentials.secretAccessKey);
  console.log("SessionToken:", AWS.config.credentials.sessionToken);
});
```

That returned a valid `ASIA...` temporary access key, secret key, and session token — real AWS credentials, issued to an anonymous browser tab that had done nothing to prove who I was.

Then, instead of calling `getItem` for just my own guest record like the app does, I called `scan` on the whole table:

```javascript
const dynamodb = new AWS.DynamoDB({ region: "us-east-1" });
dynamodb.scan({ TableName: "complimentary-GuestWellnessProfiles" }, function(err, data) {
  if (err) console.error("Scan error:", err);
  else console.log(JSON.stringify(data, null, 2));
});
```

No `AccessDeniedException`. It came back with all five guest records in the table, including full names, emails, phone numbers, locations, and *plaintext passwords* — none of which had anything to do with my own guest session. One record, guest `guest-vip-042`, existed purely to point out what had just happened:

> "If you're reading this, the wellness app's guest role can read every profile, not just its own. `THM{fr33_app_fr33_d4t4!}`"

**Flag: `THM{fr33_app_fr33_d4t4!}`**

## Why this worked

This one didn't require bypassing anything — the credentials I used were the exact same ones the app hands out to every single visitor by design. The actual failure was entirely on the AWS side, not the app logic:

- **Unauthenticated identity pools are supposed to be low-trust by default.** Cognito absolutely supports handing out real, temporary AWS credentials to unauthenticated users — that's a legitimate pattern for things like anonymous analytics or public read access. The problem isn't that the pool has an unauth role; it's what that role is allowed to *do*.
- **The IAM policy attached to the unauth role was scoped to the table, not to the operation or the record.** The app's own frontend code only ever calls `GetItem` on a specific `guest_id`. But IAM permissions don't inherit restrictions from how the frontend *intends* to use them — if the policy grants `dynamodb:Scan` (or a wildcard like `dynamodb:*`) on the table, anyone holding those credentials can call any DynamoDB action the policy allows, regardless of what the JS was written to do.
- **The frontend's restraint was cosmetic, not a security boundary.** `app.js` politely asking for only your own record is a UX choice, not an access control. Nothing on the client side can enforce "only fetch your own data" once the actual AWS credentials in your hands are broader than that — the real permission boundary has to exist in IAM, not in which SDK calls the app's JavaScript happens to make.
- **"Read-only" wasn't scoped to "read your own item."** The room's briefing line about this being "technically" consensual, read-only access says it well: read-only access to an entire table of other people's contacts, locations, and passwords is not the same thing as read-only access to your own record, even though both get described the same way in a permissions prompt.

## How I'd fix it

- **Scope the IAM policy down to the specific action the app actually needs**, i.e. `dynamodb:GetItem` only, not `Scan`, `Query`, or a wildcard — and never grant unauth roles broad table-level access when the use case is "read your own record."
- **Use fine-grained access control (IAM condition keys / `LeadingKeys`) tied to the Cognito identity ID**, so even `GetItem` can only ever retrieve the item whose partition key matches the caller's own `cognito-identity.amazonaws.com:sub`. This turns "the app only asks for your own data" into an actual enforced boundary instead of a polite convention.
- **Don't store secrets like plaintext passwords in a guest-readable table at all.** Even with tighter IAM scoping, storing raw passwords in DynamoDB is a second failure independent of the access control issue — that data shouldn't be retrievable in plaintext by anything, including the legitimate owner's own session.
- **Treat unauthenticated Cognito credentials as fully public.** Anyone can obtain them from any browser with zero verification, so the permissions attached to that role should be audited as if they're being handed directly to a stranger — because they are.

## What I learned

This room made the client-side vs. backend distinction really concrete. The frontend code was, in a narrow sense, "well-behaved" — it only ever asked for one guest's record. But well-behaved frontend code means nothing if the credentials backing it aren't equally restricted, because anyone can open DevTools and just... not use the frontend. The actual security boundary in a Cognito-based app has to live in the IAM policy attached to the identity pool role, not in the JavaScript that happens to ship with the page.

It's also a good reminder that "free," "no login," and "read-only" are marketing language, not security guarantees. Each one described a real property of the system here (no account was needed, and yes, technically the access was read-only) — none of them said anything about *whose* data that access reached.

## Q&A

**Q: What is an AWS Cognito Identity Pool, and why does it matter for security?**

A: It's a service that issues temporary AWS credentials to app users so the app can talk directly to other AWS services (like DynamoDB or S3) without running its own backend API. It supports both authenticated users (via a login provider) and unauthenticated "guest" access. The security-relevant part is that whatever IAM role is attached to that pool's unauth path gets treated by AWS exactly like any other role — the permissions are real and enforced at the AWS level, not the app level.

**Q: How is this different from a normal broken-access-control bug?**

A: In a typical IDOR you're usually manipulating an ID or session token to trick an API into returning someone else's record through the app's own backend logic. Here there's no backend API at all to trick — the vulnerable "API" is AWS itself, and the credentials handed to me are exactly as powerful as the IAM policy allows, independent of anything the frontend code does or checks.

**Q: How do you test for this kind of vulnerability?**

A: Look for any app that skips login but still personalizes content — that's a strong signal it's using unauthenticated cloud credentials behind the scenes. Check the JS bundle for SDK config (`IdentityPoolId`, `CognitoIdentityCredentials`, Firebase config, similar patterns). Once you can obtain credentials the same way the app does, use them directly against the backend service — try broader operations (scan/list instead of get, list buckets instead of one key) than what the app's own code calls, since the credentials are rarely scoped as tightly as the intended use case.

**Q: How would you fix this one specifically?**

A: Tighten the IAM policy on the unauth role to `GetItem` only, add a condition key binding the query to the caller's own Cognito identity so even `GetItem` can't reach other records, and get plaintext passwords out of the table entirely.
