# Securing the AEC database

## Why this is needed

`database.rules.json` currently sets `".read": true, ".write": true` on `members`,
`messages`, and `dms`. Verified live from a signed-out browser:

- every member record is readable **and writable** by anyone
- passwords are unsalted SHA-256 in that readable table
- phone numbers are AES-encrypted with a key hardcoded in public JS
  (`aec-ucsb-priv-2025`), so the encryption protects nothing
- all DM threads are readable

This cannot be fixed by tightening rules alone. The rules are open *because* the
client has no credentials to present — auth is `localStorage` only. Lock the rules
down before the client can authenticate and the site stops working.

## Order of operations

Steps 1-2 are safe and independent. Do not start step 4 until step 3 is done.

### 1. Rotate your own password  ← do this first, it costs nothing

Your hash has been publicly readable. Change it on the site, and anywhere you
reused it.

### 2. Ship the safe fixes  (branch: `security-fixes`)

- `database.rules.json` — adds `track-progress`, which was missing, so
  `syncProgressToFirebase()` at `track.html:1458` has been failing silently
  (verified: 401). Module progress currently lives only in localStorage.
- `functions/index.js` — SMS links pointed at
  `quinnbaltazar.github.io/...`; now `www.ucsbaec.com`.

```bash
firebase deploy --only database          # rules
firebase deploy --only functions         # SMS URL fix
```

Neither changes auth. Nothing breaks.

### 3. Add Firebase Auth to the client

Email/Password is already enabled on the project. Each page currently talks to
RTDB over raw REST with no token — roughly 99 call sites across 7 pages. Two
options:

**a. Minimal** — keep the REST calls, append `?auth=<idToken>` from
`firebase.auth().currentUser.getIdToken()`. Smaller diff, easy to review.

**b. Proper** — load `firebase-database-compat.js` and use the SDK. Real-time
listeners, automatic token refresh. Better long-term.

Either way, `assets/app.js` becomes the single place that reads auth state,
replacing the `aec-session` localStorage read.

Convert and test one page at a time. Suggested order, least to most risky:
`topics.html` → `board.html` → `track.html` → `vote.html` → `members.html` →
`messages.html` → `admin.html` → `signin.html`.

### 4. Import existing members, then lock the rules

```bash
cd migration && npm i firebase-admin
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
node import-members.js --dry-run     # check the counts first
node import-members.js
```

Existing SHA-256 hashes import directly into Firebase Auth, so **members keep
their current passwords** — no forced reset. Anyone whose hash is missing or
malformed gets listed and needs a reset link.

Once every page authenticates and the import is verified:

```bash
cp database.rules.secure.json database.rules.json
firebase deploy --only database
```

### 5. Rotate the phone encryption key

`aec-ucsb-priv-2025` is in public git history and cannot be un-leaked. After
step 4, `members/$uid/phone` is owner-only, so the key stops being the thing
protecting it — but re-encrypt under a new key held only in function config,
and treat every phone number stored before that as compromised.

## Verifying it worked

From a signed-out browser console, each of these should return 401:

```js
const DB="https://applied-economics-club-default-rtdb.firebaseio.com";
for (const p of ["members","dms","messages","track-progress"]) {
  console.log(p, (await fetch(`${DB}/${p}.json?shallow=true`)).status);
}
```

Today they return 200.


---

## Unread-message emails

`functions/index.js` runs `sendUnreadEmailReminders` hourly. If a DM has gone
unread for 24 hours it emails the recipient, at most once per conversation per
day, and never about their own message. Members opt out by setting
`emailReminders: false` on their member record.

Twilio/SMS was removed. The per-message cost was negligible, but US A2P 10DLC
registration is ~$10-15/month regardless of volume, plus number rental — a fixed
cost for a channel email already covers.

Setup:

1. Create a free Brevo account and verify a sender address.
2. Settings -> SMTP & API -> create an API key.
3. `firebase functions:secrets:set BREVO_API_KEY`
4. Set `SENDER_EMAIL` in `functions/index.js` to the verified address.
5. `firebase deploy --only functions`

Brevo's free tier is 300 emails/day, well beyond club volume.
