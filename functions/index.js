const { onValueCreated }   = require('firebase-functions/v2/database');
const { onSchedule }       = require('firebase-functions/v2/scheduler');
const { setGlobalOptions } = require('firebase-functions/v2');
const admin                = require('firebase-admin');
const twilio               = require('twilio');
const { subtle }           = require('crypto').webcrypto;

admin.initializeApp();
setGlobalOptions({ region: 'us-central1' });

const KP   = 'aec-ucsb-priv-2025';
const SALT  = 'aec-salt-v1';

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
  const [, ivHex, b64] = v.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const ct = Buffer.from(b64, 'base64');
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, await getCK(), ct);
  return new TextDecoder().decode(pt);
}

function toE164(raw) {
  const digits = raw.replace(/\D/g, '');
  if (digits.length === 10) return '+1' + digits;
  if (digits.length === 11 && digits[0] === '1') return '+' + digits;
  return '+' + digits;
}

function eKey(email) {
  return String(email).replace(/[.@#$[\]/]/g, '_');
}

// ── Triggered SMS: fires immediately when queued by client (legacy path kept) ─
exports.sendSmsNotification = onValueCreated(
  'notifications/sms_queue/{entryId}',
  async (event) => {
    const entry   = event.data.val();
    const entryId = event.params.entryId;
    const ref     = admin.database().ref('notifications/sms_queue/' + entryId);

    try {
      if (!entry || !entry.toEmail) return;

      const memberSnap = await admin.database().ref('members/' + eKey(entry.toEmail)).get();
      const member = memberSnap.val();
      if (!member || !member.phone) return;

      const phone = await decryptField(member.phone);
      if (!phone) return;

      const accountSid = process.env.TWILIO_ACCOUNT_SID;
      const authToken  = process.env.TWILIO_AUTH_TOKEN;
      const fromNumber = process.env.TWILIO_FROM_NUMBER;

      const client = twilio(accountSid, authToken);
      const senderName = entry.senderName || 'A member';
      const preview    = entry.msgPreview  || '';

      await client.messages.create({
        to:   toE164(phone),
        from: fromNumber,
        body: `AEC message from ${senderName}: "${preview}" — reply at https://quinnbaltazar.github.io/Applied_Economics_Website/messages.html`
      });
    } catch (err) {
      console.error('SMS send failed:', err);
    } finally {
      await ref.remove();
    }
  }
);

// ── Scheduled reminder: every hour, SMS anyone with 24h+ unread messages ──────
exports.sendSmsReminders = onSchedule(
  { schedule: 'every 1 hours', region: 'us-central1' },
  async () => {
    const db  = admin.database();
    const now = Date.now();
    const ONE_DAY = 24 * 60 * 60 * 1000;

    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken  = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_FROM_NUMBER;
    const client     = twilio(accountSid, authToken);

    const dmsSnap = await db.ref('dms').get();
    const dms = dmsSnap.val();
    if (!dms) return;

    for (const [convId, conv] of Object.entries(dms)) {
      if (!conv || !conv.meta) continue;
      const meta = conv.meta;
      if (!Array.isArray(meta.participants) || !meta.lastAt) continue;

      const messageAge = now - meta.lastAt;
      if (messageAge < ONE_DAY) continue;

      for (const email of meta.participants) {
        const key    = eKey(email);
        const unread = meta['unread_' + key] || 0;
        if (unread === 0) continue;

        // Skip if we already sent an SMS reminder in the last 24h
        const lastSmsAt = meta['smsReminderAt_' + key] || 0;
        if (lastSmsAt && now - lastSmsAt < ONE_DAY) continue;

        // Only send SMS after an email notification was already sent
        const emailSentAt = meta['emailNotifiedAt_' + key] || 0;
        if (!emailSentAt) continue;

        try {
          const memberSnap = await db.ref('members/' + key).get();
          const member = memberSnap.val();
          if (!member || !member.phone) continue;

          const phone = await decryptField(member.phone);
          if (!phone) continue;

          const senderKey  = meta.lastFrom ? eKey(meta.lastFrom) : null;
          const senderName = senderKey && meta.names ? (meta.names[senderKey] || 'A member') : 'A member';

          await client.messages.create({
            to:   toE164(phone),
            from: fromNumber,
            body: `AEC reminder: You have ${unread} unread message${unread > 1 ? 's' : ''} from ${senderName}. Reply at https://quinnbaltazar.github.io/Applied_Economics_Website/messages.html`
          });

          await db.ref(`dms/${convId}/meta/smsReminderAt_${key}`).set(now);
          console.log(`SMS reminder sent to ${email} for conv ${convId}`);
        } catch (err) {
          console.error(`SMS reminder failed for ${email}:`, err);
        }
      }
    }
  }
);
