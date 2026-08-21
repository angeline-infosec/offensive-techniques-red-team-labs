Complimentary - TryHackMe Hacker's Holiday 2026
================================================================

**Room:** [Complimentary (TryHackMe Hacker's Holiday 2026)](https://tryhackme.com/room/hh-complimentary-05e0b604?vccr=1)

**Category:** Cloud - AWS Cognito / IAM Misconfiguration

**Vulnerability class:** Overly Permissive IAM Role Attached to Unauthenticated Cognito Identity Pool - related to [OWASP API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) and AWS's own guidance against granting broad table access to unauth identity pool roles.

<img width="1908" height="510" alt="Screenshot 2026-08-21 200301" src="https://github.com/user-attachments/assets/8619ed65-2c39-4b03-b884-2c49eee8b143" />


## Scenario

The Byte Lotus Wellness app is the hotel's free companion app. There's No account or login screen, just open it and it already has a name and notes waiting for you. Lambo installed it on day one, gave it the permissions it asked for, and got a tote bag for her trouble. The briefing's whole point is that "no login" doesn't mean "no credentials" something is quietly issuing AWS access behind the scenes, and whatever it is, it isn't being careful about what it hands out. The goal was to find that mechanism, get its credentials, and see how much of the app's backend data those credentials actually reach.

## First contact

I opened the target site from TryHackMe and got a plain, generic welcome screen which didn't ask for any login credentials, just straight to a dashboard:

<img width="1918" height="873" alt="Screenshot 2026-08-21 195556" src="https://github.com/user-attachments/assets/e4fa387a-16cc-4ec7-ad8d-a3614034f3d0" />


No login prompt, just a page that clearly expects to know things about visitors eventually. That "eventually" was the interesting part, something on the backend was going to start recognizing me.

## The actual move: read the client-side JS, then take its credentials for a walk

I inspected the page source and found `app.js`, which laid out the entire architecture in the comments:

<img width="672" height="268" alt="Screenshot 2026-08-21 195805" src="https://github.com/user-attachments/assets/823d54a2-c57e-4ec0-8ab4-72a946e6b259" />


So the app hands every visitor real, temporary AWS credentials from a Cognito Identity Pool with unauthenticated access enabled and no login required by design. The rest of `app.js` used those credentials to run a scoped `dynamodb.getItem()` against a table called `complimentary-GuestWellnessProfiles`, keyed to a random `guest-xxxxxxxx` ID stored in `localStorage`. In other words: the *app* only ever asked for your own record. Nothing indicates the credentials were limited to that.

I didn't have the AWS CLI installed, so instead of running commands locally I used the browser's own DevTools console. 
Since `app.js` already loads the AWS SDK on the page, I could just reuse it live. 

First, I forced the credential fetch and printed it:

```javascript
AWS.config.credentials.get(function(err) {
  if (err) { console.error("Cred error:", err); return; }
  console.log("AccessKeyId:", AWS.config.credentials.accessKeyId);
  console.log("SecretAccessKey:", AWS.config.credentials.secretAccessKey);
  console.log("SessionToken:", AWS.config.credentials.sessionToken);
});
```

<img width="1909" height="323" alt="Screenshot 2026-08-21 200955" src="https://github.com/user-attachments/assets/b1332808-503f-4f31-b81d-febdaf7f69cb" />


That returned a valid temporary access key, secret key, and session token, which are real AWS credentials, issued to an anonymous browser tab that had done nothing to prove who I was.

Then, instead of calling `getItem` for just my own guest record like the app does, I called `scan` on the whole table:

```javascript
const dynamodb = new AWS.DynamoDB({ region: "us-east-1" });
dynamodb.scan({ TableName: "complimentary-GuestWellnessProfiles" }, function(err, data) {
  if (err) console.error("Scan error:", err);
  else console.log(JSON.stringify(data, null, 2));
});
```

<img width="1919" height="871" alt="Screenshot 2026-08-21 201237" src="https://github.com/user-attachments/assets/ee3f969f-5f2d-405e-90cc-c2507c2dc6b3" />


No `AccessDeniedException`. It returned all five guest records in the table, including full names, emails, phone numbers, locations, and plaintext passwords, none of which had anything to do with my own guest session. Guest `guest-vip-042`, existed purely to point out what had just happened:

> "If you're reading this, the wellness app's guest role can read every profile, not just its own. `THM{fr33_app_fr33_d4t4!}`"

**Flag: `THM{fr33_app_fr33_d4t4!}`**

## Why this worked

This one didn't require bypassing anything. The credentials I used were the exact same ones the app hands out to every single visitor by design. The actual failure was entirely on the AWS side, not the app logic:

- **Unauthenticated identity pools are supposed to be low-trust by default.** Cognito absolutely supports handing out real, temporary AWS credentials to unauthenticated users — that's a legitimate pattern for things like anonymous analytics or public read access. The problem isn't that the pool has an unauth role; it's what that role is allowed to *do*.
- **The IAM policy attached to the unauth role was scoped to the table, not to the operation or the record.** The app's own frontend code only ever calls `GetItem` on a specific `guest_id`. But IAM permissions don't inherit restrictions from how the frontend *intends* to use them — if the policy grants `dynamodb:Scan` (or a wildcard like `dynamodb:*`) on the table, anyone holding those credentials can call any DynamoDB action the policy allows, regardless of what the JS was written to do.
- **The frontend's restraint was cosmetic, not a security boundary.** `app.js` politely asking for only your own record is a UX choice, not an access control. Nothing on the client side can enforce "only fetch your own data" once the actual AWS credentials in your hands are broader than that — the real permission boundary has to exist in IAM, not in which SDK calls the app's JavaScript happens to make.
- **"Read-only" wasn't scoped to "read your own item."** The room's briefing line about this being "technically" consensual, read-only access says it well: read-only access to an entire table of other people's contacts, locations, and passwords is not the same thing as read-only access to your own record, even though both get described the same way in a permissions prompt.

## How I'd fix it

- **Scope the IAM policy down to the specific action the app actually needs**, i.e. `dynamodb:GetItem` only, not `Scan`, `Query`, or a wildcard, and never grant unauth roles broad table-level access when the use case is "read your own record."
- **Use fine-grained access control (IAM condition keys / `LeadingKeys`) tied to the Cognito identity ID**, so even `GetItem` can only ever retrieve the item whose partition key matches the caller's own `cognito-identity.amazonaws.com:sub`. This turns "the app only asks for your own data" into an actual enforced boundary instead of a polite convention.
- **Don't store secrets like plaintext passwords in a guest-readable table at all.** Even with tighter IAM scoping, storing raw passwords in DynamoDB is a second failure independent of the access control issue that data shouldn't be retrievable in plaintext by anything, including the legitimate owner's own session.
- **Treat unauthenticated Cognito credentials as fully public.** Anyone can obtain them from any browser with zero verification, so the permissions attached to that role should be audited as if they're being handed directly to a stranger well, because they are.

## What I learned

This room made the client-side vs. backend distinction really concrete. The frontend code was, in a narrow sense, "well-behaved"; it only ever asked for one guest's record. But well-behaved frontend code means nothing if the credentials backing it aren't equally restricted, because anyone can open DevTools and just... not use the frontend. The actual security boundary in a Cognito-based app has to live in the IAM policy attached to the identity pool role, not in the JavaScript that happens to ship with the page.

It's also a good reminder that "free," "no login," and "read-only" are marketing language, not security guarantees. Each one described a real property of the system here (no account was needed, and yes, technically the access was read-only) none of them said anything about whose data that access reached.

## Q&A

**Q: What is an AWS Cognito Identity Pool, and why does it matter for security?**

A: It's a service that issues temporary AWS credentials to app users so the app can talk directly to other AWS services (like DynamoDB or S3) without running its own backend API. It supports both authenticated users (via a login provider) and unauthenticated "guest" access. The security-relevant part is that whatever IAM role is attached to that pool's unauth path gets treated by AWS exactly like any other role — the permissions are real and enforced at the AWS level, not the app level.

**Q: How is this different from a normal broken-access-control bug?**

A: In a typical IDOR you're usually manipulating an ID or session token to trick an API into returning someone else's record through the app's own backend logic. Here there's no backend API at all to trick — the vulnerable "API" is AWS itself, and the credentials handed to me are exactly as powerful as the IAM policy allows, independent of anything the frontend code does or checks.

**Q: How do you test for this kind of vulnerability?**

A: Look for any app that skips login but still personalizes content — that's a strong signal it's using unauthenticated cloud credentials behind the scenes. Check the JS bundle for SDK config (`IdentityPoolId`, `CognitoIdentityCredentials`, Firebase config, similar patterns). Once you can obtain credentials the same way the app does, use them directly against the backend service — try broader operations (scan/list instead of get, list buckets instead of one key) than what the app's own code calls, since the credentials are rarely scoped as tightly as the intended use case.

**Q: How would you fix this one specifically?**

A: Tighten the IAM policy on the unauth role to `GetItem` only, add a condition key binding the query to the caller's own Cognito identity so even `GetItem` can't reach other records, and get plaintext passwords out of the table entirely.


## Note

**What is Cognito, actually?**

It's AWS's identity service. Its job is to hand out temporary AWS credentials to app users so the app can talk directly to AWS services (DynamoDB, S3, etc.) without the developer needing to stand up their own backend API. Two flows exist: authenticated (you log in via Google/Facebook/a user pool, then get credentials tied to you) and unauthenticated (you get credentials for just showing up, no proof of identity at all). This app used the second one, by design — that's the "no login screen" pitch.

**Why would anyone do that on purpose?**

It's not inherently reckless. Plenty of legit apps use unauth Cognito for things like anonymous analytics, public read-only content, or letting a first-time visitor save preferences before they've created an account. The pattern itself is fine. What matters entirely is what IAM permissions get attached to that unauth role.

**Where was the actual bug?**

Not in the app's JavaScript — app.js behaved exactly as intended, only ever calling GetItem for your own guest_id. The bug was in AWS IAM, one layer down. The unauth role's policy granted dynamodb:Scan (or similarly broad access) on the whole table, not just GetItem scoped to your own record. IAM doesn't know or care what the frontend meant to do — it only enforces what the policy allows. Since I had the same raw credentials the page was using, I wasn't limited to the SDK calls the page's code happened to make. I could call anything the policy permitted.

**Why is that the real lesson?**

Client-side code is not a security boundary — full stop. Anything running in a browser can be inspected, and any credentials it holds can be extracted and reused outside the page entirely, via DevTools console, curl, the CLI, whatever. "The app only asks for X" is a UX detail. "The credentials can only get X" is a security control. Only the second one actually matters. This is the cloud-native cousin of "never trust client-side validation" — same principle, different layer.

**Why did scan succeed where get-item on someone else's ID wouldn't have worked as cleanly?**

GetItem needs you to already know the exact partition key (guest_id) you're asking for — you'd have had to guess or leak someone else's guest ID first. Scan doesn't require knowing anything in advance; it just reads the entire table, keys and all, in one call. So the existence of Scan permission on the unauth role turned "can't see others' data without their ID" into "can see literally everyone's data with zero prior knowledge."

**What should have been different, concretely?**

Three separate layers should have existed and didn't:

IAM policy scoped to GetItem only — no Scan, no Query, no wildcard actions.
A condition key (dynamodb:LeadingKeys) binding even GetItem to the caller's own Cognito identity ID, so the policy itself enforces "only your row," not just the app's habits.
Plaintext passwords should never have been in that table at all — that's a data-handling failure independent of the access-control one. Even the legitimate, correctly-scoped owner of a record shouldn't get their password back in plaintext from a read call.
