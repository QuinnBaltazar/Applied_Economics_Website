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

    console.log(`broadcast "${subject}" — sent:${sent} failed:${failed} skipped:${skipped}`);
    res.json({ sent, failed, skipped, errors });
  }
);


// ── Admin: tell a member their password was cleared ─────────────────────────
// POST { email }  with header  x-broadcast-key: <passphrase>
// Same passphrase as sendBroadcast; see the note on BROADCAST_KEY above.
exports.sendPasswordResetNotice = onRequest(
  {
    region: 'us-central1',
    secrets: [BREVO_API_KEY, BROADCAST_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com']
  },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }

    const provided = String(req.get('x-broadcast-key') || '');
    const expected = BROADCAST_KEY.value();
    if (!provided || provided.length !== expected.length || provided !== expected) {
      console.warn('reset notice rejected: bad key from', req.ip);
      res.status(403).json({ error: 'Not authorised' });
      return;
    }

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
   AI FEATURES — Gemini (free tier, project aec-ai)
   ════════════════════════════════════════════════════════════════════════ */

const GEMINI_API_KEY = defineSecret('GEMINI_API_KEY');
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
    `[${i + 1}] (${h.source}) ${h.title}${h.desc ? ' — ' + h.desc : ''}`).join('\n');
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
        if (model !== chain[0]) console.warn(`Gemini fell back to ${model}`);
        return parseGemini(await res.json());
      }
      const detail = (await res.text()).slice(0, 300);
      lastErr = new Error(`Gemini ${res.status}: ${detail}`);
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

function requireKey(req, res) {
  const provided = String(req.get('x-broadcast-key') || '');
  const expected = BROADCAST_KEY.value();
  if (!provided || provided.length !== expected.length || provided !== expected) {
    res.status(403).json({ error: 'Not authorised' });
    return false;
  }
  return true;
}

// ── Topic scanner ───────────────────────────────────────────────────────────
async function runTopicScan() {
  const db = admin.database();

  // Everything already on or proposed for the board, so we never re-propose.
  const [counts, custom, pending] = await Promise.all([
    db.ref('vote-counts').get(), db.ref('custom-topics').get(), db.ref('pending-topics').get()
  ]);
  const existing = [
    ...Object.keys(counts.val() || {}),
    ...Object.values(custom.val() || {}).map(t => t && t.name),
    ...Object.values(pending.val() || {}).map(t => t && t.name)
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

// Daily at 07:00 Pacific — proposals are waiting when an admin checks in.
exports.scanTopicsDaily = onSchedule(
  { schedule: 'every day 07:00', timeZone: 'America/Los_Angeles', region: 'us-central1', secrets: [GEMINI_API_KEY] },
  async () => {
    if (!(await aiBudgetOk())) { console.warn('AI daily cap reached'); return; }
    try { await runTopicScan(); } catch (e) { console.error('daily scan failed:', e.message); }
  }
);

// "Scan now" button in admin.
exports.scanTopicsNow = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY, BROADCAST_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;
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
 {"type":"stat","heading":"...","stats":[{"value":"...","label":"..."}]},
 {"type":"quote","text":"...","attribution":"..."}
]`;

function deckPrompt(topic, guidance, articles) {
  const ctx = articles && articles.length
    ? `\nRecent related headlines (numbered; cite with "refs" on any slide that uses one):\n${numberedHeadlines(articles)}\n`
    : '';
  return `You are preparing a presentation for a university Applied Economics Club meeting (~30 undergrads, mixed experience).

Topic: ${topic}
${guidance ? `Presenter guidance to follow: ${guidance}` : ''}
${ctx}

Build a 8-11 slide deck as JSON. Slide types available:
${DECK_SCHEMA}

Requirements:
- Slide 1 must be type "title".
- Mix types; never more than two "bullets" slides in a row.
- Max 5 points per slide, each under 16 words. No sub-bullets.
- Numbers policy: only use figures that appear in the headlines above or that are
  stable common knowledge (e.g. "the Fed has a dual mandate"). NEVER invent market
  data, prices, percentages or dates. Prefer qualitative framing over fake precision.
- End with discussion questions (type "bullets", heading "Discussion").

Reply with ONLY JSON: {"title":"...","subtitle":"...","slides":[...]}`;
}

function sanitizeDeck(deck, topic, sources) {
  if (!deck || !Array.isArray(deck.slides) || !deck.slides.length) {
    throw new Error('model returned no slides');
  }
  const slides = deck.slides.slice(0, 14).filter(s => s && s.type);
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
  { region: 'us-central1', secrets: [GEMINI_API_KEY, BROADCAST_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;

    const topic = String((req.body && req.body.topic) || '').trim();
    const guidance = String((req.body && req.body.guidance) || '').trim().slice(0, 1000);
    if (!topic) { res.status(400).json({ error: 'topic is required' }); return; }
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }

    try {
      // Pull current headlines and keep the ones sharing a word with the topic
      // (plus a few general ones) as citable context.
      const all = await fetchHeadlines(10);
      const words = topic.toLowerCase().split(/\W+/).filter(w => w.length > 3);
      const related = all.filter(h =>
        words.some(w => (h.title + ' ' + h.desc).toLowerCase().includes(w)));
      const articles = [...related, ...all.filter(h => !related.includes(h))].slice(0, 8);

      const { text } = await callGemini(deckPrompt(topic, guidance, articles), false);
      const parsed = extractJson(text);
      // Sources slide: only articles the model actually cited via refs.
      const cited = new Set();
      for (const sl of (parsed.slides || [])) {
        for (const n of (Array.isArray(sl.refs) ? sl.refs : [])) {
          const h = articles[Number(n) - 1];
          if (h) cited.add(h);
        }
        delete sl.refs;
      }
      const sources = [...cited].map(h => ({ title: `${h.source}: ${h.title}`.slice(0, 120), url: h.url }));
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

// ── Deck refinement — the "prompt window" in admin ──────────────────────────
exports.refineDeck = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY, BROADCAST_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;

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
- Keep the same JSON schema. Slide types: title, bullets, split, stat, quote, sources.
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
  { region: 'us-central1', secrets: [BROADCAST_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;
    const id = String((req.body && req.body.id) || '').trim();
    if (!id) { res.status(400).json({ error: 'id is required' }); return; }
    const ref = admin.database().ref('decks/' + id);
    if (!(await ref.get()).exists()) { res.status(404).json({ error: 'No deck with that id' }); return; }
    await ref.remove();
    console.log('deck deleted:', id);
    res.json({ deleted: id });
  }
);

// ── Flyers ──────────────────────────────────────────────────────────────────
// Gemini writes the copy; flyer.html renders it in club branding. All Gemini
// image models are 0/0 on the free tier, so the design is template-driven -
// which is also why it stays on-brand. Facts (dates, rooms, links) come from
// the admin and must be used verbatim; the model only writes around them.
exports.generateFlyer = onRequest(
  { region: 'us-central1', secrets: [GEMINI_API_KEY, BROADCAST_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;

    const purpose = String((req.body && req.body.purpose) || 'Recruiting').trim().slice(0, 60);
    const details = String((req.body && req.body.details) || '').trim().slice(0, 1200);
    const template = ['bold', 'story'].includes(req.body && req.body.template) ? req.body.template : 'bold';
    const style = ['bold', 'classic', 'grid'].includes(req.body && req.body.style) ? req.body.style : 'bold';
    if (!details) { res.status(400).json({ error: 'details are required - when/where/what should the flyer say?' }); return; }
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }

    const prompt =
`Write copy for a ${purpose} flyer for the UCSB Applied Economics Club (undergrad econ/finance club: weekly topic votes, industry speakers, career tracks in IB/trading/equity research/VC/consulting, member community).

Facts from the organiser - use every date, time, room and link EXACTLY as written, and invent no others:
${details}

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
      const { text } = await callGemini(prompt, false);
      const c = extractJson(text);
      if (!c || !c.headline) throw new Error('no usable copy returned');
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
  { region: 'us-central1', secrets: [GEMINI_API_KEY, BROADCAST_KEY], timeoutSeconds: 120,
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;
    const id = String((req.body && req.body.id) || '').trim();
    const instruction = String((req.body && req.body.instruction) || '').trim().slice(0, 600);
    if (!id || !instruction) { res.status(400).json({ error: 'id and instruction are required' }); return; }

    const ref = admin.database().ref('flyers/' + id);
    const flyer = (await ref.get()).val();
    if (!flyer) { res.status(404).json({ error: 'No flyer with that id' }); return; }
    if (!(await aiBudgetOk())) { res.status(429).json({ error: 'Daily AI budget reached' }); return; }

    const prompt =
`Current flyer copy for the UCSB Applied Economics Club (JSON):
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
  { region: 'us-central1', secrets: [BROADCAST_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;
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
  { region: 'us-central1', secrets: [BROADCAST_KEY],
    cors: ['https://www.ucsbaec.com', 'https://ucsbaec.com'] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
    if (!requireKey(req, res)) return;
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
