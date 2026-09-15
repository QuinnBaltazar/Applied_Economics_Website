/*
  One-time migration: RTDB members -> Firebase Auth accounts.

  Existing passwords are unsalted SHA-256, which Firebase Auth can import
  directly, so members keep the password they already use. Nobody is forced
  to reset.

  Run:
    cd migration && npm i firebase-admin
    node import-members.js --dry-run     # inspect first
    node import-members.js               # actually import
*/
// firebase-admin v13 removed the legacy admin.credential namespace from the
// CJS entry point - the modular API is the supported path.
const { initializeApp, applicationDefault } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getDatabase } = require('firebase-admin/database');
const DRY = process.argv.includes('--dry-run');

initializeApp({
  credential: applicationDefault(),
  databaseURL: 'https://applied-economics-club-default-rtdb.firebaseio.com'
});
const auth = getAuth();
const db = getDatabase();

// RTDB stores the SHA-256 as hex; Auth import wants raw bytes.
const hexToBuf = (h) =>
  /^[0-9a-f]{64}$/i.test(h || '') ? Buffer.from(h, 'hex') : null;

(async () => {
  const snap = await db.ref('members').get();
  const members = snap.val() || {};
  const users = [];
  const skipped = [];

  for (const [key, m] of Object.entries(members)) {
    const email = (m && m.email) || key.replace(/_/g, '.').replace(/\.ucsb\.edu$/, '@ucsb.edu');
    if (!email.endsWith('@ucsb.edu')) { skipped.push([key, 'not @ucsb.edu']); continue; }

    const buf = hexToBuf(m && m.password);
    if (!buf) { skipped.push([key, 'no usable password hash — will need reset']); continue; }

    users.push({
      uid: key.slice(0, 128),   // convenient, but nothing depends on uid anymore
      email,
      emailVerified: false,
      displayName: (m && m.name) || undefined,
      passwordHash: buf
    });
  }

  console.log(`ready: ${users.length}   skipped: ${skipped.length}`);
  skipped.forEach(([k, why]) => console.log(`  skip ${k}: ${why}`));

  if (DRY) { console.log('\n--dry-run: nothing written'); process.exit(0); }

  const res = await auth.importUsers(users, {
    hash: { algorithm: 'SHA256', rounds: 1 }
  });
  console.log(`imported ${res.successCount}, failed ${res.failureCount}`);
  res.errors.forEach(e => console.log(`  [${e.index}] ${e.error.message}`));
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
