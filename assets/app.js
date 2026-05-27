/* ==========================================================================
   UCSB Applied Economics Club — shared client script
   - Session-aware nav (no flash; runs ASAP in <head>)
   - Scroll-shadow on topbar
   - Reveal-on-scroll observer
   - Mobile nav toggle
   - Active-page highlight
   ========================================================================== */
(function () {
  'use strict';

  // --- 1. Auth state — must run BEFORE first paint to avoid flash ---------
  function readSession() {
    try {
      var raw = JSON.parse(localStorage.getItem('aec-session') || 'null');
      if (!raw || !raw.loginAt) return null;
      // Sessions expire after 30 days
      if (Date.now() - raw.loginAt > 30 * 24 * 60 * 60 * 1000) {
        localStorage.removeItem('aec-session');
        return null;
      }
      return raw;
    } catch (e) { return null; }
  }
  function applyAuthClass() {
    var s = readSession();
    var b = document.body || document.documentElement;
    if (s) {
      b.classList.add('is-authed');
      if (s.email === 'quinnbaltazar@ucsb.edu' || s.isAdmin === true) {
        b.classList.add('is-admin');
      }
    }
  }
  // Run as early as possible. If <body> isn't there yet, retry on
  // DOMContentLoaded — but try synchronously first.
  if (document.body) applyAuthClass();
  else document.addEventListener('DOMContentLoaded', applyAuthClass);

  // --- 2. Active-page highlight + Sign In ↔ Profile relabel ---------------
  function applyActiveNav() {
    var page = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.main-nav a').forEach(function (a) {
      a.classList.toggle('active', a.getAttribute('href') === page);
    });
    var signInLink = document.querySelector('.main-nav a[href="signin.html"]');
    if (signInLink && readSession()) signInLink.textContent = 'Profile';
  }

  // --- 3. Reveal-on-scroll ------------------------------------------------
  function setupReveal() {
    var els = document.querySelectorAll('.reveal');
    if (!els.length) return;
    if (!('IntersectionObserver' in window)) {
      els.forEach(function (e) { e.classList.add('visible'); });
      return;
    }
    var io = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    els.forEach(function (e) { io.observe(e); });
  }

  // --- 4. Mobile nav toggle -----------------------------------------------
  function setupMobileNav() {
    var btn = document.getElementById('nav-toggle');
    var nav = document.getElementById('main-nav');
    if (!btn || !nav) return;
    btn.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
      btn.classList.toggle('open', open);
      btn.setAttribute('aria-expanded', String(open));
    });
    nav.querySelectorAll('a').forEach(function (a) {
      a.addEventListener('click', function () {
        nav.classList.remove('open');
        btn.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // --- 5. Topbar scroll shadow --------------------------------------------
  function setupScrollShadow() {
    var bar = document.getElementById('topbar');
    if (!bar) return;
    window.addEventListener('scroll', function () {
      bar.classList.toggle('scrolled', window.scrollY > 8);
    }, { passive: true });
  }

  // --- Boot ---------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    applyAuthClass(); // safety net in case body wasn't there earlier
    applyActiveNav();
    setupReveal();
    setupMobileNav();
    setupScrollShadow();
  });
})();
