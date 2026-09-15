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
const { defineSecret } = require('firebase-functions/params');
const { setGlobalOptions } = require('firebase-functions/v2');
const admin = require('firebase-admin');
const { subtle } = require('crypto').webcrypto;

admin.initializeApp();
setGlobalOptions({ region: 'us-central1' });

const BREVO_API_KEY = defineSecret('BREVO_API_KEY');

// Must be a sender address verified in your Brevo account, or sends fail.
// Using a personal Gmail for now. Gmail's DMARC policy means Brevo sends this
// "on behalf of" the address, so some clients show a "via brevo" note and it is
// more likely to land in spam. Switching to noreply@ucsbaec.com once the domain
// is verified in Brevo fixes both.
const SENDER_EMAIL = 'quinnbaltazar@gmail.com';
const SENDER_NAME  = 'UCSB Applied Economics Club';
const SITE_URL     = 'https://www.ucsbaec.com';

const ONE_DAY = 24 * 60 * 60 * 1000;

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
  footer:   'Sent once per conversation per day. Turn these off in your profile.'
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
  { schedule: 'every 1 hours', region: 'us-central1', secrets: [BREVO_API_KEY] },
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
      if (now - meta.lastAt < ONE_DAY) continue;

      for (const email of meta.participants) {
        const key = eKey(email);

        const unread = meta['unread_' + key] || 0;
        if (unread === 0) continue;

        // Don't nag: at most one reminder per conversation per day.
        const lastReminder = meta['emailReminderAt_' + key] || 0;
        if (lastReminder && now - lastReminder < ONE_DAY) { skipped++; continue; }

        // Never remind someone about their own message.
        if (meta.lastFrom && eKey(meta.lastFrom) === key) continue;

        try {
          const memberSnap = await db.ref('members/' + key).get();
          const member = memberSnap.val();
          if (!member) { skipped++; continue; }

          // Members can opt out.
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
