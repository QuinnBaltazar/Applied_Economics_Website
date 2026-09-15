# Auth cutover — the runbook

The branch `auth-migration` IS the migration. One coordinated cutover:

## 1. Import existing members into Firebase Auth (FIRST — before pushing)

Members keep their current passwords (SHA-256 hashes import natively).

```bash
cd migration && npm i firebase-admin
# service account: Firebase console -> Project settings -> Service accounts
#   -> Generate new private key -> save the json OUTSIDE the repo
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
node import-members.js --dry-run     # read the counts + skips first
node import-members.js
```

Anyone listed as skipped (plaintext or missing password) signs in via
"Forgot password" — Firebase emails them a secure reset link.

## 2. Ship everything at once

```bash
git push origin main
firebase deploy --only database,functions
```

Push and deploy back-to-back: the locked rules and the token-attaching
pages must land together. In the minute between, signed-out visitors see
empty lists — fine at club scale.

## 3. Tell members one thing

"Sign in again at ucsbaec.com/signin.html — same email, same password."
Old localStorage sessions are decorative now; a real sign-in mints the
token everything else uses.

## 4. What changed, security-wise

- Identity = Google-signed ID token, verified by rules and by functions.
  localStorage forgery changes pixels only.
- Passwords: Firebase Auth only. The member record cannot even contain a
  password field (rules validate it away). Resets are Firebase links.
- isAdmin: immutable to its owner at rules level; changed only via the
  adminMember function, which requires a verified admin token.
- members/dms/progress/submissions/votes: signed-in members only; own-key
  writes bound to the token email. Outsiders: no read, no write.
- decks/flyers stay world-readable (public present/flyer pages) and
  functions-write-only. The admin passphrase is gone everywhere.

## Known v1 boundaries (deliberate)

- Member-vs-member tamper on shared nodes (vote-counts, topics, message
  board) is possible — bounded to signed-in @ucsb.edu members and logged
  in activity. Locking those to admin-only writes means routing normal
  member actions through functions; do later if it ever matters.
- Phone ciphertext is readable by signed-in members (rules cascade); the
  decrypt key is still client-side. Narrowed from world -> members. Full
  fix = server-side re-encryption; queued behind real-world need.
