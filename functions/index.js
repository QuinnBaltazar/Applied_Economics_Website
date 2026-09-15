/*
  UCSB AEC — Cloud Functions

  One scheduled job: if a DM goes unread for 24 hours, email the recipient.

  Why a scheduled function rather than the client:
  EmailJS runs in the browser, so it can only fire while someone has the page
  open. "Unread for a day" needs code that runs on a timer with nobody
  watching, which is what this is.

  SETUP
    1. Create a free Brevo account (brevo.com) and verify a sender address.
    2. Settings -> SMTP & API -> create an API key.
    3. Store it as a secret (the value never goes in this file or in git):
         firebase functions:secrets:set BREVO_API_KEY
    4. Set SENDER_EMAIL below to the address you verified in step 1.
    5. firebase deploy --only functions
*/

const { onSchedule }  = require('firebase-functions/v2/scheduler');
const { onRequest }   = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const { setGlobalOptions } = require('firebase-functions/v2');
const admin = require('firebase-admin');
const { subtle } = require('crypto').webcrypto;

admin.initializeApp();
setGlobalOptions({ region: 'us-central1' });

const BREVO_API_KEY  = defineSecret('BREVO_API_KEY');
// Passphrase the admin types in admin.html to authorise a broadcast.
// admin.html's own admin check is client-side only, so it cannot protect an
// HTTP endpoint — anyone can call the URL directly. This shared secret is the
// stopgap until the site moves to Firebase Auth (see migration/RUNBOOK.md),
// at which point this should become a proper auth-token check.
const BROADCAST_KEY = defineSecret('BROADCAST_KEY');

// Must be a sender address verified in your Brevo account, or sends fail.
// Using a personal Gmail for now. Gmail's DMARC policy means Brevo sends this
// "on behalf of" the address, so some clients show a "via brevo" note and it is
// more likely to land in spam. Switching to noreply@ucsbaec.com once the domain
// is verified in Brevo fixes both.
const SENDER_EMAIL = 'quinnbaltazar@gmail.com';
const SENDER_NAME  = 'UCSB Applied Economics Club';
const SITE_URL     = 'https://www.ucsbaec.com';

// A message unread for this long triggers a reminder.
const REMIND_AFTER = 60 * 60 * 1000;   // 1 hour

// ── Email wording ───────────────────────────────────────────────────────────
// Edit these freely. Placeholders are substituted before sending:
//   {count}   number of unread messages   e.g. 3
//   {s}       "s" when count > 1, else ""  e.g. "message{s}" -> "messages"
//   {sender}  who sent the last message    e.g. Samuel Millen
//   {name}    the recipient's name
const COPY = {
  subject:  'You have {count} unread message{s} in AEC',
  heading:  'You have {count} unread message{s}',
  body:     '{sender} messaged you in the Applied Economics Club and you haven\'t read it yet.',
  button:   'Read it',
  footer:   'Sent once per conversation until you read it. Turn these off in your profile.'
};

function fill(tpl, vars) {
  return tpl.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

// ── preferredEmail is stored encrypted; decrypt it to know where to send ────
// NOTE: this key is also present in client-side JS and in git history, so it
// offers no real protection. See migration/RUNBOOK.md — it should be rotated
// once members/$uid is no longer world-readable.
const KP = 'aec-ucsb-priv-2025';
const SALT = 'aec-salt-v1';

let _ck = null;
async function getCK() {
  if (_ck) return _ck;
  const enc = new TextEncoder();
  const raw = await subtle.importKey('raw', enc.encode(KP), 'PBKDF2', false, ['deriveKey']);
  _ck = await subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(SALT), iterations: 100000, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  return _ck;
}

async function decryptField(v) {
  if (!v || !String(v).startsWith('enc:')) return v;
  try {
    const [, ivHex, b64] = String(v).split(':');
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: Buffer.from(ivHex, 'hex') },
      await getCK(),
      Buffer.from(b64, 'base64')
    );
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

function eKey(email) {
  return String(email).replace(/[.@#$[\]/]/g, '_');
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function sendEmail(apiKey, to, toName, senderName, unreadCount) {
  const vars = {
    count:  unreadCount,
    s:      unreadCount > 1 ? 's' : '',
    sender: esc(senderName),
    name:   esc(toName || 'there')
  };

  const body = {
    sender: { name: SENDER_NAME, email: SENDER_EMAIL },
    to: [{ email: to, name: toName || undefined }],
    subject: fill(COPY.subject, vars),
    htmlContent:
      `<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#111">` +
        `<h2 style="margin:0 0 12px;font-size:19px">${fill(COPY.heading, vars)}</h2>` +
        `<p style="margin:0 0 20px;line-height:1.5;color:#444">${fill(COPY.body, vars)}</p>` +
        `<a href="${SITE_URL}/messages.html" style="display:inline-block;background:#C4A448;color:#111;` +
          `padding:11px 20px;border-radius:7px;text-decoration:none;font-weight:600">${fill(COPY.button, vars)}</a>` +
        `<p style="margin:26px 0 0;font-size:12px;color:#888">${fill(COPY.footer, vars)}</p>` +
      `</div>`
  };

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': apiKey,
      'content-type': 'application/json',
      'accept': 'application/json'
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    throw new Error(`Brevo ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
}

// ── Hourly: email anyone sitting on a DM unread for 24h+ ────────────────────
exports.sendUnreadEmailReminders = onSchedule(
  { schedule: 'every 15 minutes', region: 'us-central1', secrets: [BREVO_API_KEY] },
  async () => {
    const db = admin.database();
    const now = Date.now();
    const apiKey = BREVO_API_KEY.value();

    const snap = await db.ref('dms').get();
    const dms = snap.val();
    if (!dms) { console.log('no conversations'); return; }

    let sent = 0, skipped = 0, failed = 0;

    for (const [convId, conv] of Object.entries(dms)) {
      const meta = conv && conv.meta;
      if (!meta || !Array.isArray(meta.participants) || !meta.lastAt) continue;

      // Not old enough yet.
      if (now - meta.lastAt < REMIND_AFTER) continue;

      for (const email of meta.participants) {
        const key = eKey(email);

        const unread = meta['unread_' + key] || 0;
        if (unread === 0) continue;

        // One reminder per unread streak. Opening the thread clears this flag
        // (see messages.html), so reading resets the clock and a later message
        // can trigger a fresh reminder.
        if (meta['emailReminderAt_' + key]) { skipped++; continue; }

        // Never remind someone about their own message.
        if (meta.lastFrom && eKey(meta.lastFrom) === key) continue;

        try {
          const memberSnap = await db.ref('members/' + key).get();
          const member = memberSnap.val();
          if (!member) { skipped++; continue; }

          // On by default: only an explicit false opts out.
          if (member.emailReminders === false) { skipped++; continue; }

          const to = (await decryptField(member.preferredEmail)) || email;
          if (!to || !to.includes('@')) { skipped++; continue; }

          const senderKey = meta.lastFrom ? eKey(meta.lastFrom) : null;
          const senderName =
            (senderKey && meta.names && meta.names[senderKey]) || 'Another member';

          await sendEmail(apiKey, to, member.name, senderName, unread);
          await db.ref(`dms/${convId}/meta/emailReminderAt_${key}`).set(now);
          sent++;
        } catch (err) {
          failed++;
          console.error(`reminder failed for ${key} in ${convId}:`, err.message);
        }
      }
    }

    console.log(`unread reminders — sent:${sent} skipped:${skipped} failed:${failed}`);
  }
);


// ── Admin: email every member ───────────────────────────────────────────────
// POST { subject, body }  with header  x-broadcast-key: <passphrase>
// Recipients are sent individually so nobody sees anyone else's address.
exports.sendBroadcast = onRequest(
  {
    region: 'us-central1',
    secrets: [BREVO_API_KEY, BROADCAST_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com']
  },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }

    // Constant-time-ish comparison; reject before doing any work.
    const provided = String(req.get('x-broadcast-key') || '');
    const expected = BROADCAST_KEY.value();
    if (!provided || provided.length !== expected.length || provided !== expected) {
      console.warn('broadcast rejected: bad key from', req.ip);
      res.status(403).json({ error: 'Not authorised' });
      return;
    }

    const subject = String((req.body && req.body.subject) || '').trim();
    const bodyText = String((req.body && req.body.body) || '').trim();
    if (!subject || !bodyText) {
      res.status(400).json({ error: 'subject and body are both required' });
      return;
    }
    if (subject.length > 200 || bodyText.length > 20000) {
      res.status(400).json({ error: 'subject or body too long' });
      return;
    }

    const db = admin.database();

    // Cooldown, so a stuck button can't mail everyone repeatedly.
    const lastRef = db.ref('admin/lastBroadcastAt');
    const lastAt = (await lastRef.get()).val() || 0;
    if (Date.now() - lastAt < 60 * 1000) {
      res.status(429).json({ error: 'A broadcast was just sent. Wait a minute.' });
      return;
    }
    await lastRef.set(Date.now());

    const membersSnap = await db.ref('members').get();
    const members = membersSnap.val() || {};
    const apiKey = BREVO_API_KEY.value();

    // Preserve the author's line breaks without letting them inject markup.
    const htmlBody = esc(bodyText).replace(/\n/g, '<br>');

    let sent = 0, failed = 0, skipped = 0;
    const errors = [];

    for (const [key, member] of Object.entries(members)) {
      if (!member) { skipped++; continue; }
      const to = (await decryptField(member.preferredEmail))
              || (member.email || key.replace(/_/g, '.').replace(/\.ucsb\.edu$/, '@ucsb.edu'));
      if (!to || !to.includes('@')) { skipped++; continue; }

      try {
        const r = await fetch('https://api.brevo.com/v3/smtp/email', {
          method: 'POST',
          headers: {
            'api-key': apiKey,
            'content-type': 'application/json',
            'accept': 'application/json'
          },
          body: JSON.stringify({
            sender: { name: SENDER_NAME, email: SENDER_EMAIL },
            to: [{ email: to, name: member.name || undefined }],
            subject,
            htmlContent:
              `<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;` +
                `max-width:520px;margin:0 auto;padding:24px;color:#111">` +
                `<p style="margin:0 0 18px;line-height:1.6;font-size:15px">${htmlBody}</p>` +
                `<p style="margin:28px 0 0;font-size:12px;color:#888;border-top:1px solid #eee;padding-top:14px">` +
                  `Sent to all members of the UCSB Applied Economics Club.` +
                `</p>` +
              `</div>`
          })
        });
        if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 120)}`);
        sent++;
      } catch (err) {
        failed++;
        if (errors.length < 5) errors.push(`${key}: ${err.message}`);
      }
    }

    console.log(`broadcast "${subject}" — sent:${sent} failed:${failed} skipped:${skipped}`);
    res.json({ sent, failed, skipped, errors });
  }
);
