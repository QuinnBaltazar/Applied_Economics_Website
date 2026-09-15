/*
  UCSB AEC, Cloud Functions

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
// offers no real protection. See migration/RUNBOOK.md, it should be rotated
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

// ── Who to send to ──────────────────────────────────────────────────────────
// UCSB addresses stop working after graduation, so current students get both
// their UCSB and personal address, while alumni get the personal one only.
//
// gradYear is either a year string ("2027") or the literal "Alumni". UCSB
// commencement is in June, so someone whose gradYear matches the current year
// counts as alumni from July onward.
function hasGraduated(gradYear, now = new Date()) {
  if (!gradYear) return false;                    // unknown - assume current
  if (String(gradYear).trim().toLowerCase() === 'alumni') return true;
  const y = parseInt(gradYear, 10);
  if (!Number.isFinite(y)) return false;
  const thisYear = now.getFullYear();
  if (y < thisYear) return true;
  if (y > thisYear) return false;
  return now.getMonth() >= 6;                     // July (0-indexed) or later
}

// Returns a de-duplicated list of Brevo recipients.
function recipientsFor(member, ucsbEmail, personalEmail, now = new Date()) {
  const name = member && member.name ? member.name : undefined;
  const out = [];
  const seen = new Set();
  const add = (addr) => {
    const a = String(addr || '').trim().toLowerCase();
    if (!a || !a.includes('@') || seen.has(a)) return;
    seen.add(a);
    out.push({ email: a, name });
  };

  if (hasGraduated(member && member.gradYear, now)) {
    add(personalEmail);
    add(ucsbEmail);          // fallback only - no personal address on file
    return out.slice(0, 1);  // alumni: personal only
  }

  add(ucsbEmail);
  add(personalEmail);
  return out;
}

function eKey(email) {
  return String(email).replace(/[.@#$[\]/]/g, '_');
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function sendEmail(apiKey, recipients, toName, senderName, unreadCount) {
  const vars = {
    count:  unreadCount,
    s:      unreadCount > 1 ? 's' : '',
    sender: esc(senderName),
    name:   esc(toName || 'there')
  };

  const body = {
    sender: { name: SENDER_NAME, email: SENDER_EMAIL },
    to: recipients,
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

          const personal = await decryptField(member.preferredEmail);
          const recipients = recipientsFor(member, email, personal);
          if (!recipients.length) { skipped++; continue; }

          const senderKey = meta.lastFrom ? eKey(meta.lastFrom) : null;
          const senderName =
            (senderKey && meta.names && meta.names[senderKey]) || 'Another member';

          await sendEmail(apiKey, recipients, member.name, senderName, unread);
          await db.ref(`dms/${convId}/meta/emailReminderAt_${key}`).set(now);
          sent++;
        } catch (err) {
          failed++;
          console.error(`reminder failed for ${key} in ${convId}:`, err.message);
        }
      }
    }

    console.log(`unread reminders, sent:${sent} skipped:${skipped} failed:${failed}`);
  }
);


// ── Admin: email every member ───────────────────────────────────────────────
// POST { subject, body }  with header  x-broadcast-key: <passphrase>
// Recipients are sent individually so nobody sees anyone else's address.
exports.sendBroadcast = onRequest(
  {
    region: 'us-central1',
    secrets: [BREVO_API_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com']
  },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }

    if (!(await requireAdmin(req, res))) return;

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
      const ucsb = member.email || key.replace(/_/g, '.').replace(/\.ucsb\.edu$/, '@ucsb.edu');
      const personal = await decryptField(member.preferredEmail);
      const recipients = recipientsFor(member, ucsb, personal);
      if (!recipients.length) { skipped++; continue; }

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
            to: recipients,
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

    console.log(`broadcast "${subject}", sent:${sent} failed:${failed} skipped:${skipped}`);
    res.json({ sent, failed, skipped, errors });
  }
);


// ── Admin: tell a member their password was cleared ─────────────────────────
// POST { email }  with header  x-broadcast-key: <passphrase>
// Admin-token gated like everything else.
exports.sendPasswordResetNotice = onRequest(
  {
    region: 'us-central1',
    secrets: [BREVO_API_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com']
  },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }

    if (!(await requireAdmin(req, res))) return;

    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    if (!email || !email.includes('@')) {
      res.status(400).json({ error: 'A member email is required' });
      return;
    }

    const snap = await admin.database().ref('members/' + eKey(email)).get();
    const member = snap.val();
    if (!member) { res.status(404).json({ error: 'No member with that address' }); return; }

    const personal = await decryptField(member.preferredEmail);
    const recipients = recipientsFor(member, email, personal);
    if (!recipients.length) { res.status(400).json({ error: 'No usable address on file' }); return; }

    const name = esc(member.name || 'there');
    try {
      const r = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          'api-key': BREVO_API_KEY.value(),
          'content-type': 'application/json',
          'accept': 'application/json'
        },
        body: JSON.stringify({
          sender: { name: SENDER_NAME, email: SENDER_EMAIL },
          to: recipients,
          subject: 'Your AEC password has been reset',
          htmlContent:
            `<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;` +
              `max-width:480px;margin:0 auto;padding:24px;color:#111">` +
              `<h2 style="margin:0 0 12px;font-size:19px">Your password was reset</h2>` +
              `<p style="margin:0 0 18px;line-height:1.55;color:#444">` +
                `Hi ${name}, an admin cleared the password on your Applied Economics Club ` +
                `account. Sign in with your UCSB email to verify it and choose a new one.` +
              `</p>` +
              `<a href="${SITE_URL}/signin.html" style="display:inline-block;background:#C4A448;` +
                `color:#111;padding:11px 20px;border-radius:7px;text-decoration:none;` +
                `font-weight:600">Set a new password</a>` +
              `<p style="margin:26px 0 0;font-size:12px;color:#888">` +
                `If you did not expect this, reply to this email and let us know.` +
              `</p>` +
            `</div>`
        })
      });
      if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`);
      console.log(`reset notice sent to ${eKey(email)}`);
      res.json({ sent: true, recipients: recipients.length });
    } catch (err) {
      console.error('reset notice failed:', err.message);
      res.status(502).json({ error: 'Send failed', detail: err.message });
    }
  }
);

/* ════════════════════════════════════════════════════════════════════════
   AI FEATURES, Gemini (free tier, project aec-ai)
   ════════════════════════════════════════════════════════════════════════ */

const GEMINI_API_KEY = defineSecret('GEMINI_API_KEY');
const BRAVE_API_KEY  = defineSecret('BRAVE_API_KEY');   // optional; research works without it (Wikipedia + Commons + RSS)
// gemini-2.5-flash was retired for new API users (404: "no longer available
// to new users"); 3.6-flash is its named replacement. The lite models are the
// fallback chain: separate (larger) free quotas - 15 RPM / 500 RPD vs 5/20 -
// and they rarely hit the capacity 503s the flagship gets at peak. Slightly
// weaker models, but our prompts hand them the facts, so extraction quality
// holds up.
// Task-based routing. The flagship pool is only 20 req/day; the lite pools
// are 500/day each. So the scarce flagship goes to member-facing prose
// (decks, flyers) and the plentiful lite models handle extraction work
// (topic scans), where the facts arrive in the prompt and model strength
// matters least. Each chain still ends in the other pool as a fallback.
const QUALITY_CHAIN = ['gemini-3.6-flash', 'gemini-3.5-flash-lite', 'gemini-3.1-flash-lite'];
const BULK_CHAIN    = ['gemini-3.5-flash-lite', 'gemini-3.1-flash-lite', 'gemini-3.6-flash'];

// Free tier gives Gemini 3.x models ZERO google_search grounding quota
// (AI Studio -> Rate Limit -> Tools: "Gemini 3 / Search grounding 0"), so a
// grounded call 429s immediately. Current events come from finance RSS feeds
// instead: we fetch real headlines and the model may only cite from them,
// which also means it cannot fabricate a source. If the project ever moves
// to a paid tier, grounding can be re-enabled here.
const USE_SEARCH_GROUNDING = false;

const NEWS_FEEDS = [
  { name: 'CNBC',        url: 'https://www.cnbc.com/id/100003114/device/rss/rss.html' },
  { name: 'MarketWatch', url: 'https://feeds.content.dowjones.io/public/rss/mw_topstories' },
  { name: 'Yahoo Finance', url: 'https://finance.yahoo.com/news/rssindex' }
];

function stripXml(t) {
  return String(t || '')
    .replace(/<!\[CDATA\[(.*?)\]\]>/gs, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'")
    .replace(/\s+/g, ' ').trim();
}

// Pull recent items from the finance feeds. Tiny regex parse, no deps.
async function fetchHeadlines(maxPerFeed = 10) {
  const items = [];
  for (const feed of NEWS_FEEDS) {
    try {
      const res = await fetch(feed.url, {
        headers: { 'user-agent': 'Mozilla/5.0 (AEC club site; contact ucsbaec.com)' }
      });
      if (!res.ok) continue;
      const xml = await res.text();
      for (const m of xml.matchAll(/<item[\s>][\s\S]*?<\/item>/g)) {
        const block = m[0];
        const grab = tag => {
          const mm = block.match(new RegExp('<' + tag + '[^>]*>([\\s\\S]*?)</' + tag + '>', 'i'));
          return mm ? stripXml(mm[1]) : '';
        };
        const title = grab('title'), link = grab('link');
        if (!title || !/^https?:\/\//i.test(link)) continue;
        items.push({
          source: feed.name, title: title.slice(0, 160),
          url: link, desc: grab('description').slice(0, 240)
        });
        if (items.filter(i => i.source === feed.name).length >= maxPerFeed) break;
      }
    } catch (e) {
      console.warn('feed failed:', feed.name, e.message);
    }
  }
  return items;
}

function numberedHeadlines(items) {
  return items.map((h, i) =>
    `[${i + 1}] (${h.source}) ${h.title}${h.desc ? ', ' + h.desc : ''}`).join('\n');
}

// Hard daily cap across ALL AI calls. The free tier allows far more; this is
// a circuit breaker so a bug or abuse can't hammer the API.
const AI_DAILY_CAP = 40;

async function aiBudgetOk() {
  const day = new Date().toISOString().slice(0, 10);
  const ref = admin.database().ref('ai-usage/' + day);
  // Transaction, not read-then-set: two simultaneous calls at the cap could
  // otherwise both pass the check.
  const result = await ref.transaction(n => (n || 0) + 1);
  return (result.snapshot.val() || 0) <= AI_DAILY_CAP;
}

// Telemetry for the admin AI-status banner. Google never announces free
// tier changes; the first sign is always our own calls failing in a new
// way. Fire-and-forget so health writes can never break a real request.
function recordAiHealth(bucket, extra) {
  const day = new Date().toISOString().slice(0, 10);
  const ref = admin.database().ref('ai-health/' + day);
  ref.child(bucket).transaction(n => (n || 0) + 1).catch(() => {});
  if (extra) ref.child('last').set({ ...extra, at: Date.now() }).catch(() => {});
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// One call to Gemini, resilient by design. Walks the model chain; within a
// model, retries capacity errors (503/500/504) with backoff. Quota errors
// (429) and missing models (404) skip straight to the next model, since
// each has its own quota pool. Internal retries do NOT consume extra
// aiBudgetOk slots - the budget counts user actions, not HTTP attempts.
async function callGemini(prompt, useSearch, chain = QUALITY_CHAIN) {
  const body = {
    contents: [{ role: 'user', parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.4, maxOutputTokens: 8192 }
  };
  if (useSearch && USE_SEARCH_GROUNDING) body.tools = [{ google_search: {} }];

  let lastErr = null;
  for (const model of chain) {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) await sleep(2000 * attempt + Math.random() * 1000);
      let res;
      try {
        res = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY.value()}`,
          { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
        );
      } catch (e) {
        lastErr = new Error(`Gemini network: ${e.message}`);
        continue;                                   // transient - retry same model
      }
      if (res.ok) {
        recordAiHealth('ok');
        if (model !== chain[0]) {
          console.warn(`Gemini fell back to ${model}`);
          recordAiHealth('fallbacks', { kind: 'fallback', model });
        }
        return parseGemini(await res.json());
      }
      const detail = (await res.text()).slice(0, 300);
      lastErr = new Error(`Gemini ${res.status}: ${detail}`);
      const bucket = res.status === 429 ? 'err429' : res.status === 404 ? 'err404' : 'err5xx';
      recordAiHealth(bucket, { kind: bucket, model, status: res.status, detail: detail.slice(0, 140) });
      if (res.status === 429 || res.status === 404) break;   // next model
      if (![500, 503, 504].includes(res.status)) throw lastErr; // real error: stop
    }
  }
  throw lastErr || new Error('Gemini: all models failed');
}

function parseGemini(data) {

  const cand = data.candidates && data.candidates[0];
  const text = ((cand && cand.content && cand.content.parts) || [])
    .map(p => p.text || '').join('');

  // Grounded source URLs, if any.
  const sources = [];
  const chunks = cand && cand.groundingMetadata && cand.groundingMetadata.groundingChunks;
  if (Array.isArray(chunks)) {
    for (const c of chunks) {
      if (c.web && c.web.uri) sources.push({ title: c.web.title || c.web.uri, url: c.web.uri });
    }
  }
  return { text, sources };
}

// Models wrap JSON in prose or fences; dig the first JSON value out.
function extractJson(text) {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const raw = fenced ? fenced[1] : text;
  const start = raw.search(/[[{]/);
  if (start === -1) throw new Error('no JSON in model output');
  for (let end = raw.length; end > start; end--) {
    try { return JSON.parse(raw.slice(start, end)); } catch { /* trim and retry */ }
  }
  throw new Error('unparseable JSON in model output');
}

// Admins see this in the status line - turn Gemini's JSON blobs into English.
function friendlyAiError(e) {
  const m = String(e && e.message || e);
  if (/503|UNAVAILABLE|high demand/i.test(m))
    return 'Google\u2019s model is at capacity right now (their side, not ours). It retried and fell back automatically \u2014 wait a minute and try once more.';
  if (/429|quota|RESOURCE_EXHAUSTED/i.test(m))
    return 'Free-tier AI quota is used up for today. It resets at midnight Pacific.';
  if (/no JSON|unparseable|no slides/i.test(m))
    return 'The model returned something unusable \u2014 try again; if it repeats, simplify the topic or guidance.';
  if (/only \d+ headlines/i.test(m))
    return 'Could not fetch enough news headlines to source topics \u2014 the feeds may be briefly unreachable. Try again shortly.';
  return m.slice(0, 200);
}

// The club owner is always an admin, even if the database record is missing.
const OWNER_EMAIL = 'quinnbaltazar@ucsb.edu';

// Verifies a Firebase ID token from "Authorization: Bearer <token>" and
// checks the caller's member record for isAdmin. This replaces the shared
// passphrase: identity is cryptographic (Google-signed token, spoofable by
// nobody), and the admin flag lives in a database node clients can no
// longer write. Returns the caller's email, or null after responding 403.
async function requireAdmin(req, res) {
  try {
    const m = String(req.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
    if (!m) { res.status(401).json({ error: 'Sign in required' }); return null; }
    const decoded = await admin.auth().verifyIdToken(m[1]);
    const email = String(decoded.email || '').toLowerCase();
    if (!email.endsWith('@ucsb.edu')) {
      res.status(403).json({ error: 'UCSB account required' }); return null;
    }
    if (email === OWNER_EMAIL) return email;
    const rec = (await admin.database().ref('members/' + eKey(email)).get()).val();
    if (rec && rec.isAdmin === true) return email;
    res.status(403).json({ error: 'Admin access required' });
    return null;
  } catch (e) {
    res.status(401).json({ error: 'Session expired - reload and sign in again' });
    return null;
  }
}

// ── Topic scanner ───────────────────────────────────────────────────────────
async function runTopicScan() {
  const db = admin.database();

  // Everything already on or proposed for the board, so we never re-propose.
  const [counts, custom, pending, decks] = await Promise.all([
    db.ref('vote-counts').get(), db.ref('custom-topics').get(), db.ref('pending-topics').get(), db.ref('decks').get()
  ]);
  const existing = [
    ...Object.keys(counts.val() || {}),
    ...Object.values(custom.val() || {}).map(t => t && t.name),
    ...Object.values(pending.val() || {}).map(t => t && t.name),
    ...Object.values(decks.val() || {}).map(d => d && d.title)   // just-presented sessions
  ].filter(Boolean);

  const headlines = await fetchHeadlines(10);
  if (headlines.length < 5) {
    throw new Error(`only ${headlines.length} headlines fetched - refusing to scan without real sources`);
  }

  const prompt =
`You help a university Applied Economics Club pick weekly discussion topics that members vote on.

Below are today's real finance/markets headlines, numbered. Propose exactly 5 discussion topics grounded in them.

HEADLINES:
${numberedHeadlines(headlines)}

Rules:
- Every topic must be based on one or more of the numbered headlines. Include their numbers in "refs".
- Each topic needs: "name" (max 60 chars, punchy, board-ready), "desc" (2 sentences: what happened and why it matters), "refs" (array of headline numbers used).
- Never use em dashes in any text; use commas or periods.
- Do NOT propose anything similar to these existing topics: ${existing.join('; ') || '(none)'}
- Do not invent facts beyond the headlines. If fewer than 5 topics are well-supported, return fewer.

Reply with ONLY a JSON array: [{"name":"...","desc":"...","refs":[1,2]}]`;

  const { text } = await callGemini(prompt, false, BULK_CHAIN);
  const topics = extractJson(text);
  if (!Array.isArray(topics)) throw new Error('expected a JSON array of topics');

  let added = 0;
  for (const t of topics.slice(0, 5)) {
    if (!t || !t.name || !t.desc) continue;
    // Sources are the exact fetched articles the model cited - it cannot
    // fabricate a URL because it never outputs one.
    const refs = (Array.isArray(t.refs) ? t.refs : [])
      .map(n => headlines[Number(n) - 1]).filter(Boolean);
    if (!refs.length) continue;   // unsourced topic: dropped
    await db.ref('pending-topics').push({
      name: String(t.name).slice(0, 80),
      desc: String(t.desc).slice(0, 500),
      createdBy: 'AI scanner',
      ai: true,
      sources: refs.slice(0, 4).map(h => ({ title: `${h.source}: ${h.title}`.slice(0, 120), url: h.url })),
      createdAt: Date.now()
    });
    added++;
  }
  console.log(`topic scan: proposed ${added} from ${headlines.length} headlines`);
  return { proposed: added, headlines: headlines.length };
}

// Daily at 07:00 Pacific, proposals are waiting when an admin checks in.
exports.scanTopicsDaily = onSchedule(
  { schedule: 'every day 07:00', timeZone: 'America/Los_Angeles', region: 'us-central1', secrets: [GEMINI_API_KEY] },
  async () => {
    if (!(await aiBudgetOk())) { console.warn('AI daily cap reached'); return; }
    try { await runTopicScan(); } catch (e) { console.error('daily scan failed:', e.message); }
  }
);

// "Scan now" button in admin.
exports.scanTopicsNow = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }
    try { res.json(await runTopicScan()); }
    catch (e) { console.error('scan failed:', e.message); res.status(502).json({ error: friendlyAiError(e) }); }
  }
);

// ── Deck generator ──────────────────────────────────────────────────────────
// A deck is structured JSON in decks/{id}; present.html renders it. Slides:
//   {type:"title",   heading, sub}
//   {type:"bullets", heading, points:[str]}
//   {type:"split",   heading, left:{title,points}, right:{title,points}}
//   {type:"stat",    heading, stats:[{value,label}]}
//   {type:"quote",   text, attribution}
//   {type:"sources", links:[{title,url}]}
const DECK_SCHEMA = `[
 {"type":"title","heading":"...","sub":"..."},
 {"type":"bullets","heading":"...","points":["..."]},
 {"type":"split","heading":"...","left":{"title":"...","points":["..."]},"right":{"title":"...","points":["..."]}},
 {"type":"cards","heading":"...","numbered":true,"cards":[{"title":"...","body":"1-2 sentence explanation"}]},
 {"type":"stat","heading":"...","stats":[{"value":"...","label":"what this number means, in plain words"}]},
 {"type":"chart","heading":"...","chartType":"line|bar","points":[{"label":"Q1","value":12.4}],"note":"source or 'illustrative'"},
 {"type":"cycle","heading":"...","stages":["Accumulation","Markup","Distribution","Markdown"],"note":"optional"},
 {"type":"image","heading":"...","imageRef":1,"caption":"one-line caption"},
 {"type":"quote","text":"...","attribution":"..."}
]
Every slide except "title" may also carry:
 "kicker": "SECTION \u00b7 DETAIL"  (short uppercase eyebrow, e.g. "METHODOLOGY \u00b7 IDENTIFICATION")
 "sub": "one italic line of context under the heading"
 "src": "short citation for facts on this slide, e.g. 'Kuttner (2001); FRED'"
 "notes": "speaker notes (see NOTES below)"`;

function deckPrompt(topic, guidance, research, brief) {
  research = research || {};
  const ctx = research.context
    ? `\nRESEARCH (numbered sources — cite with "refs":[n] on any slide that uses a fact from one):\n${research.context}\n`
    : '';
  const imgs = research.imageList
    ? `\nAVAILABLE IMAGES (real, free, licensed — reference by number with "imageRef", never invent a URL):\n${research.imageList}\n`
    : '';
  return `${brief || CLUB_BRIEF}

You are preparing a presentation for this club's weekly meeting (~30 undergrads, mixed experience).

Topic: ${topic}
${guidance ? `Presenter guidance to follow: ${guidance}` : ''}
${ctx}${imgs}

Build a 8-11 slide deck as JSON. Slide types available:
${DECK_SCHEMA}

RIGOR (this is a finance club; members will notice hand-waving):
- Teach REAL, established, nameable frameworks. If the topic has documented
  theory, name it and attribute it: e.g. Wyckoff accumulation/markup/distribution/
  markdown phases; sector rotation across the business cycle; the four economic
  cycle stages; mean reversion; momentum. Explain how the actual concept works.
- Do NOT invent authoritative-sounding specifics. "Data center capex drives the
  early markup phase" is a fabricated causal claim, avoid that kind of thing.
- When you give an example, label it plainly ("For example, hypothetically...")
  so it reads as illustration, not a sourced fact.
- NEVER invent market data, prices, percentages, dates, or firm-specific claims.
  If a real figure is not in the headlines above and not stable common knowledge,
  frame it qualitatively instead.
- If you are not confident something is established and correct, leave it out.
  A shorter, correct deck beats a longer, plausible-sounding one.

VISUALS (use them, a finance deck should not be all text):
- Use a "chart" slide when you have at least two REAL data points (from the
  headlines above or stable common knowledge). Its numbers must be real; if you
  do not have real figures, do NOT fabricate a chart, use a "cycle" or "stat"
  instead. Add note:"illustrative" only if the shape is conceptual.
- Use a "cycle" slide to show a conceptual sequence of stages (market cycle,
  Wyckoff phases, sector rotation, a process). This is schematic, so it is the
  right way to show a concept without implying fake precision.
- Use an "image" slide to show a real, relevant picture from AVAILABLE IMAGES
  above. Set "imageRef" to the image's number. Only use an image that genuinely
  fits the point; do NOT force one. Never invent an image or a URL.
- Aim for at least two visual slides (chart, cycle, stat, or image) in the deck.

STYLE (this club has a house style; follow it on every slide):
- Every slide except the title gets a "kicker": a short uppercase eyebrow like
  "FED SURPRISES \u00b7 METHODOLOGY" or "KEY PAPER \u00b7 QJE 2025" naming the
  section plus the specific context.
- Headings state the TAKEAWAY, not the topic. "Larger surprises, larger sector
  reactions" beats "Results". Add a "sub" line for context where useful.
- Use "cards" (2x2 grid) for methodology steps, framework components,
  contributions, and the closing pitch. Set "numbered":true when order matters.
  Card titles are punchy; bodies are 1-2 full sentences that actually explain.
- Stats are never bare numbers: every "label" says what the number MEANS
  ("Fed meetings in our sample", "decline by October 2025"). 2-4 per slide.
- Give facts a "src" line (short citation) whenever they come from the research
  above or a nameable source.
- Be honest about uncertainty: include a limitations point or slide where
  relevant. Prefix supported findings with "\u2713 " and limitations with
  "\u2013 "; this is how strong decks earn trust.

NOTES (required on every content slide):
- "notes" is the presenter's script: 2-5 sentences of what to actually SAY, in
  plain spoken English, not a repeat of the slide text.
- Start with a timing tag like "[1 min]" and end with "TRANSITION: <one line
  leading into the next slide>".

ARC (order the deck like an argument, not a list):
1. "title"
2. Hook: why this matters right now (stat or bullets, kicker "WHY IT MATTERS")
3. The core question or framework, named and attributed
4. Evidence and mechanics: how it works, real examples (chart, cycle, image, cards)
5. Implications: what a student investor should do with this
6. Closing: numbered "cards" slide answering "Why does this matter?"
7. Final "bullets" slide, heading "Discussion", 3-4 open questions
- Mix types; never two same-type slides in a row (bullets may repeat once).
- Max 5 points per list, each under 16 words. No sub-bullets.

Reply with ONLY JSON: {"title":"...","subtitle":"...","slides":[...]}`;
}

function sanitizeDeck(deck, topic, sources) {
  if (!deck || !Array.isArray(deck.slides) || !deck.slides.length) {
    throw new Error('model returned no slides');
  }
  const slides = deck.slides.slice(0, 14).filter(s => s && s.type && !s._drop);
  if (sources.length) {
    slides.push({ type: 'sources', links: sources.slice(0, 8) });
  }
  return {
    title: String(deck.title || topic).slice(0, 120),
    subtitle: String(deck.subtitle || 'UCSB Applied Economics Club').slice(0, 160),
    topic: String(topic).slice(0, 120),
    slides
  };
}

exports.generateDeck = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY, BRAVE_API_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;

    const topic = String((req.body && req.body.topic) || '').trim();
    const guidance = String((req.body && req.body.guidance) || '').trim().slice(0, 1000);
    if (!topic) { res.status(400).json({ error: 'topic is required' }); return; }
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }

    try {
      // Research the topic: Wikipedia + Brave web search + RSS news, ranked and
      // trimmed, plus real free licensed images the model can place in slides.
      const research = await buildResearch(topic, { news: true });
      const cites = research.cites || [];
      const imgs = research.images || [];

      const { text } = await callGemini(deckPrompt(topic, guidance, research, await clubBrain()), false);
      const parsed = extractJson(text);

      // Map cited refs -> real sources; map imageRef -> a real fetched image.
      const cited = new Set();
      for (const sl of (parsed.slides || [])) {
        for (const n of (Array.isArray(sl.refs) ? sl.refs : [])) {
          const c = cites[Number(n) - 1];
          if (c) cited.add(c);
        }
        delete sl.refs;
        if (sl.type === 'image') {
          const im = imgs[Number(sl.imageRef) - 1];
          if (im && im.url) {
            sl.url = im.url;
            sl.credit = im.source + (im.license ? ' \u00b7 ' + im.license : '');
            if (im.url) cited.add({ title: (im.caption || 'Image') + ' \u2014 ' + im.source, url: im.url });
          } else { sl._drop = true; }  // model referenced an image that does not exist
          delete sl.imageRef;
        }
      }
      const sources = [...cited].map(c => ({ title: String(c.title).slice(0, 120), url: c.url }));
      const deck = sanitizeDeck(parsed, topic, sources);
      const ref = await admin.database().ref('decks').push({
        ...deck,
        version: 1,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
      console.log(`deck generated: ${ref.key} "${deck.title}" (${deck.slides.length} slides)`);
      res.json({ id: ref.key, title: deck.title, slides: deck.slides.length });
    } catch (e) {
      console.error('deck generation failed:', e.message);
      res.status(502).json({ error: friendlyAiError(e) });
    }
  }
);

// ── Deck refinement, the "prompt window" in admin ──────────────────────────
exports.refineDeck = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;

    const id = String((req.body && req.body.id) || '').trim();
    const instruction = String((req.body && req.body.instruction) || '').trim().slice(0, 1000);
    if (!id || !instruction) { res.status(400).json({ error: 'id and instruction are required' }); return; }

    const ref = admin.database().ref('decks/' + id);
    const snap = await ref.get();
    const deck = snap.val();
    if (!deck) { res.status(404).json({ error: 'No deck with that id' }); return; }
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }

    const prompt = `Here is a presentation deck as JSON for a university Applied Economics Club:

${JSON.stringify({ title: deck.title, subtitle: deck.subtitle, slides: deck.slides })}

Revise it according to this instruction from the presenter:
"${instruction}"

Rules:
- Keep the same JSON schema. Slide types: title, bullets, split, cards, stat, chart, cycle, image, quote, sources.\n- Preserve each slide's kicker/sub/src/notes fields unless the instruction changes them.
- Change only what the instruction asks for; keep everything else intact.
- Keep any "sources" slide unless told to remove it.
- NEVER invent market data, prices, percentages or dates; if the instruction asks
  for numbers you do not reliably know, use qualitative framing instead.

Reply with ONLY the full revised JSON: {"title":"...","subtitle":"...","slides":[...]}`;

    try {
      const { text } = await callGemini(prompt, false);
      const revised = extractJson(text);
      if (!revised || !Array.isArray(revised.slides) || !revised.slides.length) {
        throw new Error('revision returned no slides');
      }
      // Keep the outgoing version so a bad revision right before a meeting is
      // recoverable (decks/{id}/history/{version}). Bounded to the last 5.
      const v = deck.version || 1;
      await ref.child('history/' + v).set({
        title: deck.title || '', subtitle: deck.subtitle || '',
        slides: deck.slides, savedAt: Date.now()
      });
      const hist = (await ref.child('history').get()).val() || {};
      const keys = Object.keys(hist).map(Number).sort((a, b) => a - b);
      for (const k of keys.slice(0, Math.max(0, keys.length - 5))) {
        await ref.child('history/' + k).remove();
      }
      await ref.update({
        title: String(revised.title || deck.title).slice(0, 120),
        subtitle: String(revised.subtitle || deck.subtitle || '').slice(0, 160),
        slides: revised.slides.slice(0, 16),
        version: (deck.version || 1) + 1,
        updatedAt: Date.now(),
        lastInstruction: instruction
      });
      console.log(`deck ${id} refined -> v${(deck.version || 1) + 1}`);
      res.json({ id, version: (deck.version || 1) + 1, slides: revised.slides.length });
    } catch (e) {
      console.error('refine failed:', e.message);
      res.status(502).json({ error: friendlyAiError(e) });
    }
  }
);

// ── Admin: delete a deck ────────────────────────────────────────────────────
// decks is write:false at the rules level, so deletion has to come through
// here (Admin SDK bypasses rules). Passphrase-gated like the rest.
exports.deleteDeck = onRequest(
  { region: 'us-central1',     cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;
    const id = String((req.body && req.body.id) || '').trim();
    if (!id) { res.status(400).json({ error: 'id is required' }); return; }
    const ref = admin.database().ref('decks/' + id);
    if (!(await ref.get()).exists()) { res.status(404).json({ error: 'No deck with that id' }); return; }
    await ref.remove();
    console.log('deck deleted:', id);
    res.json({ deleted: id });
  }
);

// ── Club brief ──────────────────────────────────────────────────────────────
// Injected into every flyer and deck prompt so the model writes from real
// identity instead of guessing. Edit freely - this is the one place the
// club describes itself to the AI.
// ══ Club brain ══════════════════════════════════════════════════════════════
// One shared context assembled from live club state and injected into every
// AI surface (decks, flyers, tutor, topic scanner). Cached 5 minutes per
// instance so it costs almost nothing.
let _brainCache = { text: null, at: 0 };
async function clubBrain() {
  if (_brainCache.text && Date.now() - _brainCache.at < 5 * 60 * 1000) return _brainCache.text;
  const parts = [CLUB_BRIEF];
  const db = admin.database();
  // Verified placements: strongest recruiting copy there is. Board-curated.
  try {
    const raw = (await db.ref('placements').get()).val() || {};
    const firms = [...new Set(Object.values(raw)
      .filter(x => x && x.name && x.type !== 'org').map(x => x.name.trim()))];
    if (firms.length) parts.push(`Verified member placements you may cite: ${firms.join(', ')}.`);
  } catch (e) { /* skip */ }
  // What members are voting on right now (top of the leaderboard).
  try {
    const counts = (await db.ref('vote-counts').get()).val() || {};
    const top = Object.entries(counts).filter(([, v]) => Number(v) > 0)
      .sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k} (${v})`);
    if (top.length) parts.push(`Topics members are voting on right now: ${top.join('; ')}.`);
  } catch (e) { /* skip */ }
  // What the club covered recently (deck titles), newest first.
  try {
    const decks = (await db.ref('decks').get()).val() || {};
    const recent = Object.values(decks)
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
      .slice(0, 4).map(d => d.title).filter(Boolean);
    if (recent.length) parts.push(`Recent session decks (do not repeat these topics): ${recent.join('; ')}.`);
  } catch (e) { /* skip */ }
  _brainCache = { text: parts.join('\n'), at: Date.now() };
  return _brainCache.text;
}
const clubBriefLive = clubBrain;   // existing call sites keep working

const CLUB_BRIEF = `ABOUT THE CLUB (use this to inform everything you write):
UCSB Applied Economics Club (ucsbaec.com). Undergraduate club at UC Santa Barbara, open to all majors.
What makes it different: members VOTE each week on what the club covers next - the agenda is member-driven, not board-driven.
What members get:
- Weekly sessions on the topic members voted for, with real market context
- Industry speakers (finance, consulting, tech)
- Career tracks with hands-on modules: Investment Banking, Trading, Equity Research, Venture Capital, Consulting, AdTech - build a DCF, tear down an M&A deal, write a stock initiation report
- A member community: directory, messaging, and presentations built for every meeting
Audience: ambitious undergrads who want practical finance/econ skills and a network, from freshmen to seniors. No experience required.
Voice: confident, concrete, student-to-student. Name real things (tracks, voting, speakers) instead of vague benefits. Never use cliches like "join our community", "fun and exciting", or stacked exclamation marks. Never use em dashes; use commas or periods instead.`;

// ══ Research pipeline: Wikipedia (keyless) + Brave (optional key) + RSS ══════
// Feeds the free model real, sourced context and real licensed images. Every
// source degrades gracefully: a failure just contributes nothing.

function relevanceScore(text, topic) {
  const terms = topic.toLowerCase().split(/\W+/).filter(w => w.length > 3);
  const t = String(text).toLowerCase();
  let n = 0; for (const w of terms) if (t.includes(w)) n++;
  return n;
}

// Top Wikipedia articles: intro text + a real original image each.
async function wikiResearch(topic) {
  const out = { chunks: [], images: [], sources: [] };
  try {
    const url = 'https://en.wikipedia.org/w/api.php?action=query&generator=search' +
      '&gsrsearch=' + encodeURIComponent(topic) + '&gsrlimit=3' +
      '&prop=extracts|pageimages|info&inprop=url&exintro=1&explaintext=1&exchars=900' +
      '&piprop=original&format=json&origin=*';
    const res = await fetch(url, { headers: { 'user-agent': 'AEC club site (ucsbaec.com)' } });
    if (!res.ok) return out;
    const data = await res.json();
    const pages = (data.query && data.query.pages) ? Object.values(data.query.pages) : [];
    pages.sort((a, b) => (a.index || 99) - (b.index || 99));
    for (const pg of pages.slice(0, 3)) {
      if (pg.extract) {
        out.chunks.push({ source: 'Wikipedia: ' + pg.title, text: pg.extract.slice(0, 900), url: pg.fullurl || ('https://en.wikipedia.org/wiki/' + encodeURIComponent(pg.title)) });
        out.sources.push({ title: 'Wikipedia: ' + pg.title, url: pg.fullurl || ('https://en.wikipedia.org/wiki/' + encodeURIComponent(pg.title)) });
      }
      if (pg.original && pg.original.source && /\.(jpg|jpeg|png|svg)$/i.test(pg.original.source)) {
        out.images.push({ url: pg.original.source, caption: pg.title, source: 'Wikipedia' });
      }
    }
  } catch (e) { console.warn('wiki research failed:', e.message); }
  return out;
}

// Fetch a web page and reduce it to clean readable text (paragraphs preferred).
// Runs server-side during deck generation; capped and fail-soft.
async function fetchPageText(url, maxLen) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(url, { headers: { 'user-agent': 'Mozilla/5.0 (compatible; AEC-club/1.0; +https://ucsbaec.com)' }, redirect: 'follow', signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) return '';
    if (!/text\/html|text\/plain/i.test(res.headers.get('content-type') || '')) return '';
    let html = (await res.text()).slice(0, 400000);
    html = html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ')
               .replace(/<(nav|header|footer|aside|form)[\s\S]*?<\/\1>/gi, ' ');
    const paras = (html.match(/<p[^>]*>([\s\S]*?)<\/p>/gi) || []).map(x => x.replace(/<[^>]+>/g, ' '));
    let text = (paras.length >= 3 ? paras.join(' ') : html.replace(/<[^>]+>/g, ' '));
    text = text.replace(/&[a-z#0-9]+;/gi, ' ').replace(/\s+/g, ' ').trim();
    return text.slice(0, maxLen || 4500);
  } catch (e) { return ''; }
}

// Spend-guard: Brave's plan bills $5/1000 requests but grants $5 free credit
// monthly (= ~1000 requests). We hard-cap at 800/month so the card on file is
// never charged; past the cap, research silently runs on the free sources.
const BRAVE_MONTHLY_CAP = 800;
function braveMonthKey() { return 'brave-usage/' + new Date().toISOString().slice(0, 7); }
async function braveBudgetOk() {
  try {
    const snap = await admin.database().ref(braveMonthKey()).get();
    return (snap.val() || 0) < BRAVE_MONTHLY_CAP;
  } catch (e) { return false; }   // if unsure, don't spend
}
function braveCount() {
  admin.database().ref(braveMonthKey())
    .transaction(n => (n || 0) + 1).catch(() => {});
}

// Brave web search (only if a key is configured).
async function braveSearch(topic) {
  const out = { chunks: [], sources: [] };
  let key = null;
  try { key = BRAVE_API_KEY.value() || process.env.BRAVE_API_KEY || null; } catch (e) { key = process.env.BRAVE_API_KEY || null; }
  if (!key) return out;   // no key configured -> research runs free on Wikipedia + Commons + RSS
  if (!(await braveBudgetOk())) { console.warn('brave monthly cap reached; using free sources'); return out; }
  try {
    const res = await fetch('https://api.search.brave.com/res/v1/web/search?q=' +
      encodeURIComponent(topic) + '&count=6&freshness=py', {
      headers: { 'Accept': 'application/json', 'X-Subscription-Token': key }
    });
    braveCount();   // count every billed API call, ok or not
    if (!res.ok) return out;
    const data = await res.json();
    const results = (data.web && data.web.results) || [];
    for (const r of results.slice(0, 6)) {
      const txt = [r.title, r.description].filter(Boolean).join(' , ');
      if (txt) {
        out.chunks.push({ source: r.profile && r.profile.name ? r.profile.name : 'Web', text: txt.slice(0, 500), url: r.url });
        if (r.url) out.sources.push({ title: (r.title || r.url).slice(0, 100), url: r.url });
      }
    }
    // Pull the actual article text from the top results (the real quality lever).
    const top = results.filter(r => r.url).slice(0, 3);
    const bodies = await Promise.all(top.map(r => fetchPageText(r.url, 4500)));
    top.forEach((r, i) => {
      const body = bodies[i];
      if (body && body.length > 250) {
        out.chunks.push({ source: (r.profile && r.profile.name ? r.profile.name : 'Web') + ' (article)', text: body, url: r.url });
      }
    });
  } catch (e) { console.warn('brave search failed:', e.message); }
  return out;
}

// Wikimedia Commons: a huge library of freely-licensed images. Returns real,
// attributable pictures relevant to the topic (photos, diagrams, examples).
async function commonsImages(topic) {
  const out = [];
  try {
    const url = 'https://commons.wikimedia.org/w/api.php?action=query&generator=search' +
      '&gsrsearch=' + encodeURIComponent(topic + ' filetype:bitmap') +
      '&gsrnamespace=6&gsrlimit=8&prop=imageinfo&iiprop=url|extmetadata|size' +
      '&iiurlwidth=1200&format=json&origin=*';
    const res = await fetch(url, { headers: { 'user-agent': 'AEC club site (ucsbaec.com)' } });
    if (!res.ok) return out;
    const data = await res.json();
    const pages = (data.query && data.query.pages) ? Object.values(data.query.pages) : [];
    for (const pg of pages) {
      const info = pg.imageinfo && pg.imageinfo[0];
      if (!info) continue;
      const src = info.thumburl || info.url;
      if (!src || !/\.(jpg|jpeg|png|svg)$/i.test(src)) continue;
      if ((info.width && info.width < 300) || (info.height && info.height < 200)) continue;
      const meta = info.extmetadata || {};
      const artist = meta.Artist && meta.Artist.value ? String(meta.Artist.value).replace(/<[^>]+>/g, '').trim().slice(0, 60) : '';
      const license = meta.LicenseShortName && meta.LicenseShortName.value ? meta.LicenseShortName.value : 'Wikimedia Commons';
      out.push({
        url: src,
        caption: (pg.title || '').replace(/^File:/, '').replace(/\.[a-z]+$/i, '').replace(/_/g, ' ').slice(0, 80),
        source: 'Wikimedia Commons' + (artist ? ' / ' + artist : ''),
        license
      });
    }
  } catch (e) { console.warn('commons images failed:', e.message); }
  return out;
}

// Combine sources, rank by relevance, trim to a budget. Returns a context
// string, an indexed image list, and a source list.
async function buildResearch(topic, opts) {
  opts = opts || {};
  const [wiki, brave] = await Promise.all([wikiResearch(topic), braveSearch(topic)]);
  const news = opts.news ? (await fetchHeadlines(8)).map(h => ({
    source: h.source, text: (h.title + (h.desc ? ' , ' + h.desc : '')).slice(0, 300), url: h.url,
    _src: { title: h.source + ': ' + h.title, url: h.url }
  })) : [];

  let chunks = [...wiki.chunks, ...brave.chunks, ...news];
  // rank by relevance, keep the strongest, cap total size
  chunks = chunks.map(c => ({ ...c, _r: relevanceScore(c.text, topic) }))
    .sort((a, b) => b._r - a._r);
  const kept = []; let budget = 18000;
  for (const c of chunks) {
    if (budget <= 0) break;
    kept.push(c); budget -= c.text.length;
  }
  const context = kept.map((c, i) => `[${i + 1}] (${c.source}) ${c.text}`).join('\n');
  const cites = kept.map(c => ({ title: String(c.source).slice(0, 120), url: c.url })).filter(c => c.url);

  let images = [...wiki.images];
  const commons = await commonsImages(topic);
  const seen = new Set(images.map(x => x.url));
  for (const im of commons) { if (!seen.has(im.url)) { images.push(im); seen.add(im.url); } }
  images = images.slice(0, 6);
  const imageList = images.length
    ? images.map((im, i) => `Image ${i + 1}: ${im.caption} — ${im.source}${im.license ? ' [' + im.license + ']' : ''}`).join('\n')
    : '';

  const sources = [...wiki.sources, ...brave.sources,
    ...news.map(n => n._src)].filter(Boolean).slice(0, 10);

  return { context, cites, imageList, images, sources, has: kept.length > 0 };
}

// ── Flyers ──────────────────────────────────────────────────────────────────
// Gemini writes the copy; flyer.html renders it in club branding. All Gemini
// image models are 0/0 on the free tier, so the design is template-driven -
// which is also why it stays on-brand. Facts (dates, rooms, links) come from
// the admin and must be used verbatim; the model only writes around them.
// ── Flyer quality guardrails ────────────────────────────────────────────────
// Two layers before a flyer is saved. Layer 1 is programmatic and free:
// caps enforced by REJECTION (truncating mid-word was itself producing
// broken-looking copy), every digit-bearing organizer fact must appear,
// banned phrases blocked. Layer 2 is a cheap critic call on the lite chain
// that reads the copy against the organizer facts. Failures feed back into
// a regeneration, up to three attempts.
const FLYER_CAPS = { headline: 60, subhead: 90, hook: 180, cta: 110, footer: 80, bullet: 60 };

function checkFlyerCopy(c, details) {
  const problems = [];
  if (!c || typeof c !== 'object') return ['no JSON object returned'];
  if (!String(c.headline || '').trim()) problems.push('headline is empty');
  for (const [k, cap] of Object.entries(FLYER_CAPS)) {
    if (k === 'bullet') continue;
    if (String(c[k] || '').length > cap) problems.push(`${k} exceeds ${cap} characters, shorten it`);
  }
  const bullets = Array.isArray(c.bullets) ? c.bullets : [];
  if (bullets.length < 2 || bullets.length > 4) problems.push('need 2 to 4 bullets');
  bullets.forEach((b, i) => {
    if (String(b).length > FLYER_CAPS.bullet) problems.push(`bullet ${i + 1} exceeds ${FLYER_CAPS.bullet} characters`);
  });

  const all = JSON.stringify(c).toLowerCase();
  // every organizer token containing a digit (dates, times, rooms) must appear
  for (const tok of String(details).split(/[\s,]+/)) {
    const t = tok.replace(/^[^\w]+/, '').replace(/[^\w:]+$/, '');
    if (t.length >= 2 && /\d/.test(t) && !all.includes(t.toLowerCase())) {
      problems.push(`organizer fact "${t}" is missing from the copy`);
    }
  }
  if (all.includes('\u2014')) problems.push('remove em dashes, use commas');
  for (const bad of ['join our community', 'fun and exciting', '!!']) {
    if (all.includes(bad)) problems.push(`remove the phrase or pattern "${bad}"`);
  }
  return problems;
}

async function criticFlyerCopy(c, details, purpose) {
  const prompt =
`You are proofreading ${purpose} flyer copy for a university economics club. Organizer facts:
${details}

Copy (JSON): ${JSON.stringify(c)}

Check: dates, times, rooms and links match the facts exactly; no invented specifics; spelling and grammar; the copy makes sense to a student walking past. Reply ONLY JSON: {"ok":true} or {"ok":false,"problems":["..."]}`;
  try {
    const { text } = await callGemini(prompt, false, BULK_CHAIN);
    const v = extractJson(text);
    if (v && v.ok === true) return [];
    return (v && Array.isArray(v.problems) && v.problems.length)
      ? v.problems.map(String).slice(0, 6) : ['critic rejected the copy'];
  } catch (e) {
    return [];   // critic unavailable: programmatic checks stand alone
  }
}

exports.generateFlyer = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;

    const purpose = String((req.body && req.body.purpose) || 'Recruiting').trim().slice(0, 60);
    const details = String((req.body && req.body.details) || '').trim().slice(0, 1200);
    const template = ['bold', 'story'].includes(req.body && req.body.template) ? req.body.template : 'bold';
    const style = ['bold', 'classic', 'grid'].includes(req.body && req.body.style) ? req.body.style : 'bold';
    if (!details) { res.status(400).json({ error: 'details are required - when/where/what should the flyer say?' }); return; }
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }

    const prompt =
`${await clubBriefLive()}

Write copy for a ${purpose} flyer for this club.

Facts from the organiser - use every date, time, room and link EXACTLY as written, and invent no others:
${details}

Make the copy highlight what the club actually IS (the voting mechanic, the career tracks, the speakers) - not generic club-fair filler.

Reply with ONLY JSON:
{
 "headline": "max 6 words, punchy, no exclamation spam",
 "subhead": "one line, max 12 words",
 "hook": "one sentence that makes a student stop walking, max 22 words",
 "bullets": ["3-4 concrete reasons to come, each max 8 words"],
 "cta": "action line with the key when/where from the facts, max 14 words",
 "footer": "one short line, e.g. all majors welcome"
}`;

    try {
      let c = null, problems = [], attempt = 0;
      for (attempt = 1; attempt <= 3; attempt++) {
        const attemptPrompt = problems.length
          ? prompt + `\n\nYour previous attempt was rejected for these reasons, fix every one:\n- ${problems.join('\n- ')}`
          : prompt;
        const { text } = await callGemini(attemptPrompt, false);
        c = extractJson(text);
        problems = checkFlyerCopy(c, details);
        if (!problems.length) problems = await criticFlyerCopy(c, details, purpose);
        if (!problems.length) break;
        console.warn(`flyer attempt ${attempt} rejected:`, problems.join(' | '));
      }
      if (problems.length) {
        res.status(422).json({ error: 'Three attempts failed quality checks: ' +
          problems.slice(0, 3).join('; ') + '. Adjust the details and try again.' });
        return;
      }
      const flyer = {
        purpose,
        template,
        style,
        headline: String(c.headline).slice(0, 60),
        subhead: String(c.subhead || '').slice(0, 90),
        hook: String(c.hook || '').slice(0, 180),
        bullets: (Array.isArray(c.bullets) ? c.bullets : []).slice(0, 4).map(b => String(b).slice(0, 60)),
        cta: String(c.cta || '').slice(0, 110),
        footer: String(c.footer || 'ucsbaec.com').slice(0, 80),
        details,
        version: 1, createdAt: Date.now(), updatedAt: Date.now()
      };
      const ref = await admin.database().ref('flyers').push(flyer);
      console.log(`flyer generated: ${ref.key} "${flyer.headline}"`);
      res.json({ id: ref.key, headline: flyer.headline });
    } catch (e) {
      console.error('flyer generation failed:', e.message);
      res.status(502).json({ error: friendlyAiError(e) });
    }
  }
);

exports.refineFlyer = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;
    const id = String((req.body && req.body.id) || '').trim();
    const instruction = String((req.body && req.body.instruction) || '').trim().slice(0, 600);
    if (!id || !instruction) { res.status(400).json({ error: 'id and instruction are required' }); return; }

    const ref = admin.database().ref('flyers/' + id);
    const flyer = (await ref.get()).val();
    if (!flyer) { res.status(404).json({ error: 'No flyer with that id' }); return; }
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }

    const prompt =
`${await clubBriefLive()}

Current flyer copy for this club (JSON):
${JSON.stringify({ headline: flyer.headline, subhead: flyer.subhead, hook: flyer.hook, bullets: flyer.bullets || [], cta: flyer.cta, footer: flyer.footer })}

Organiser facts (dates/times/rooms/links must be used exactly, never invented):
${flyer.details || '(none)'}

Revise per this instruction, changing only what it asks: "${instruction}"
Keep the same JSON shape and the same length limits.
Reply with ONLY the full revised JSON.`;

    try {
      const { text } = await callGemini(prompt, false);
      const c = extractJson(text);
      if (!c || !c.headline) throw new Error('no usable copy returned');
      await ref.update({
        headline: String(c.headline).slice(0, 60),
        subhead: String(c.subhead || '').slice(0, 90),
        hook: String(c.hook || '').slice(0, 180),
        bullets: (Array.isArray(c.bullets) ? c.bullets : []).slice(0, 4).map(b => String(b).slice(0, 60)),
        cta: String(c.cta || '').slice(0, 110),
        footer: String(c.footer || '').slice(0, 80),
        version: (flyer.version || 1) + 1, updatedAt: Date.now(), lastInstruction: instruction
      });
      res.json({ id, version: (flyer.version || 1) + 1 });
    } catch (e) {
      console.error('flyer refine failed:', e.message);
      res.status(502).json({ error: friendlyAiError(e) });
    }
  }
);

exports.deleteFlyer = onRequest(
  { region: 'us-central1',     cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;
    const id = String((req.body && req.body.id) || '').trim();
    if (!id) { res.status(400).json({ error: 'id is required' }); return; }
    const ref = admin.database().ref('flyers/' + id);
    if (!(await ref.get()).exists()) { res.status(404).json({ error: 'No flyer with that id' }); return; }
    await ref.remove();
    res.json({ deleted: id });
  }
);

// ── Admin: direct flyer edits (no AI, no budget) ────────────────────────────
// The edit mode in flyer.html collects the fields and saves them here
// verbatim. Whitelisted and length-capped; bumps version like a refine.
exports.updateFlyer = onRequest(
  { region: 'us-central1',     cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!(await requireAdmin(req, res))) return;
    const id = String((req.body && req.body.id) || '').trim();
    const f = (req.body && req.body.fields) || {};
    if (!id) { res.status(400).json({ error: 'id is required' }); return; }

    const ref = admin.database().ref('flyers/' + id);
    const cur = (await ref.get()).val();
    if (!cur) { res.status(404).json({ error: 'No flyer with that id' }); return; }

    const str = (v, n) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, n);
    const upd = {};
    if ('headline' in f) upd.headline = str(f.headline, 60);
    if ('subhead' in f) upd.subhead = str(f.subhead, 90);
    if ('hook' in f) upd.hook = str(f.hook, 180);
    if ('cta' in f) upd.cta = str(f.cta, 110);
    if ('footer' in f) upd.footer = str(f.footer, 80);
    if ('bullets' in f && Array.isArray(f.bullets)) {
      upd.bullets = f.bullets.map(b => str(b, 60)).filter(Boolean).slice(0, 5);
    }
    if ('style' in f && ['bold', 'classic', 'grid'].includes(f.style)) upd.style = f.style;
    if ('template' in f && ['bold', 'story'].includes(f.template)) upd.template = f.template;
    if ('logoPos' in f && ['left', 'center', 'right'].includes(f.logoPos)) upd.logoPos = f.logoPos;
    if ('showCrest' in f) upd.showCrest = !!f.showCrest;
    if ('showQr' in f) upd.showQr = !!f.showQr;

    if (upd.headline === '') { res.status(400).json({ error: 'headline cannot be empty' }); return; }
    if (!Object.keys(upd).length) { res.status(400).json({ error: 'nothing to update' }); return; }

    upd.version = (cur.version || 1) + 1;
    upd.updatedAt = Date.now();
    await ref.update(upd);
    res.json({ id, version: upd.version });
  }
);

// ── Admin: manage member roles and removal ──────────────────────────────────
// Direct client writes to members are locked now (and isAdmin was never safe
// to leave client-writable), so promote/demote/remove go through here.
exports.adminMember = onRequest(
  { region: 'us-central1',
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    const caller = await requireAdmin(req, res);
    if (!caller) return;

    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const action = String((req.body && req.body.action) || '');
    if (!email || !['promote', 'demote', 'remove'].includes(action)) {
      res.status(400).json({ error: 'email and a valid action are required' }); return;
    }
    if (email === OWNER_EMAIL && action !== 'promote') {
      res.status(400).json({ error: 'The owner account cannot be demoted or removed' }); return;
    }
    if (email === caller && action === 'demote') {
      res.status(400).json({ error: 'You cannot demote yourself' }); return;
    }

    const ref = admin.database().ref('members/' + eKey(email));
    if (!(await ref.get()).exists()) { res.status(404).json({ error: 'No member with that email' }); return; }

    if (action === 'remove') {
      await ref.remove();
      try { await admin.auth().deleteUser((await admin.auth().getUserByEmail(email)).uid); }
      catch (e) { /* no auth account - record-only member */ }
    } else {
      await ref.update({ isAdmin: action === 'promote' });
    }
    console.log(`adminMember: ${caller} -> ${action} ${eKey(email)}`);
    res.json({ ok: true, action, email });
  }
);

// ── Module tutor: member-facing AI, the first non-admin AI surface ─────────
// Any signed-in @ucsb.edu member may use it; the auth migration is what
// makes that safe to expose. Runs on the lite chain (500/day per model)
// with its own budgets, so it can never starve the admin flagship pool.
// Defaults; admins override live from the admin Settings panel
// (stored at config/tutor, no redeploy needed).
//
// Clamp ceilings are set by what the free tier actually serves, not by
// optimism: the tutor runs on the two lite pools (500 requests/day each,
// about 1,000 combined), which are shared with topic scans and the flyer
// quality critics. Global tops out at 800 to leave that headroom; per
// member tops out at 100 so nobody can eat the club's whole pool. If
// Google resizes the free tier, this comment and these numbers are the
// place to update.
const TUTOR_DEFAULTS = { perMember: 40, global: 600 };
const TUTOR_MAX = { perMember: 100, global: 800 };
async function tutorBudgets() {
  try {
    const c = (await admin.database().ref('config/tutor').get()).val() || {};
    const global = Math.min(TUTOR_MAX.global, Math.max(1, parseInt(c.global, 10) || TUTOR_DEFAULTS.global));
    const perMember = Math.min(TUTOR_MAX.perMember, global,
      Math.max(1, parseInt(c.perMember, 10) || TUTOR_DEFAULTS.perMember));
    return { perMember, global };
  } catch (e) { return { ...TUTOR_DEFAULTS }; }
}

async function requireMember(req, res) {
  try {
    const m = String(req.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
    if (!m) { res.status(401).json({ error: 'Sign in required' }); return null; }
    const decoded = await admin.auth().verifyIdToken(m[1]);
    const email = String(decoded.email || '').toLowerCase();
    if (!email.endsWith('@ucsb.edu')) {
      res.status(403).json({ error: 'UCSB account required' }); return null;
    }
    return email;
  } catch (e) {
    res.status(401).json({ error: 'Session expired - reload and sign in again' });
    return null;
  }
}

exports.tutorChat = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY], timeoutSeconds: 60,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    const email = await requireMember(req, res);
    if (!email) return;

    const message = String((req.body && req.body.message) || '').trim().slice(0, 1000);
    const lesson = String((req.body && req.body.lesson) || '').trim().slice(0, 5000);
    const track = String((req.body && req.body.track) || '').trim().slice(0, 80);
    const history = (Array.isArray(req.body && req.body.history) ? req.body.history : [])
      .slice(-12)
      .map(h => ({ role: h.role === 'tutor' ? 'tutor' : 'student', text: String(h.text || '').slice(0, 800) }));
    if (!message) { res.status(400).json({ error: 'Say something first' }); return; }

    // Budgets: per member per day, and a global tutor ceiling.
    const budgets = await tutorBudgets();
    const day = new Date().toISOString().slice(0, 10);
    const mine = await admin.database().ref(`ai-usage-tutor/${day}/${eKey(email)}`)
      .transaction(n => (n || 0) + 1);
    if ((mine.snapshot.val() || 0) > budgets.perMember) {
      res.status(429).json({ error: `Daily tutor limit reached (${budgets.perMember} messages). Resets at midnight Pacific.` });
      return;
    }
    const global = await admin.database().ref(`ai-usage-tutor/${day}/_total`)
      .transaction(n => (n || 0) + 1);
    if ((global.snapshot.val() || 0) > budgets.global) {
      res.status(429).json({ error: 'The tutor is resting until midnight Pacific - club-wide daily limit reached.' });
      return;
    }

    const convo = history.map(h => `${h.role === 'tutor' ? 'TUTOR' : 'STUDENT'}: ${h.text}`).join('\n');
    const prompt =
`${await clubBrain()}

You are the study tutor for this club's career-track modules. A member is working through${track ? ` the ${track} track` : ' a module'}. If they ask about the club itself (events, voting, tracks, placements), answer from the club context above.

CURRENT LESSON CONTENT (their screen right now):
${lesson || '(not provided - answer generally but say you cannot see their lesson)'}

${convo ? `CONVERSATION SO FAR:\n${convo}\n` : ''}STUDENT: ${message}

How to tutor:
- Teach, do not just answer. For quiz-style questions, guide with a hint or a leading question first; give the full answer only if they are clearly stuck or ask directly.
- Ground every explanation in the lesson content above. If they ask something outside it, answer briefly and steer back.
- Concrete and quantitative where the lesson is. Never invent market data.
- Max 150 words. Plain text, no markdown headers. Never use em dashes; use commas.
- Encouraging but not saccharine. Student-to-student register, professional.

Reply with ONLY the tutor's next message.`;

    try {
      const { text } = await callGemini(prompt, false, BULK_CHAIN);
      const reply = String(text || '').trim().slice(0, 1500);
      if (!reply) throw new Error('empty reply');
      res.json({ reply, remaining: Math.max(0, budgets.perMember - (mine.snapshot.val() || 0)) });
    } catch (e) {
      console.error('tutor failed:', e.message);
      res.status(502).json({ error: friendlyAiError(e) });
    }
  }
);
