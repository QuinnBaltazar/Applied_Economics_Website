/* ==========================================================================
   UCSB AEC, shared authentication layer (Firebase Auth, compat SDK)

   Loaded on every member page, before the page's own scripts. Three jobs:

   1. Attach the signed-in member's ID token to EVERY Realtime Database REST
      call, by wrapping window.fetch once. Pages keep their existing fbGet/
      fbSet helpers and raw fetches untouched - the token rides along
      invisibly, and the locked database rules verify it server-side.

   2. Keep the legacy localStorage 'aec-session' in sync with the REAL auth
      state, so all existing UI (nav reveal, name display, admin cosmetics)
      keeps working - but the session cache is now decoration, not identity.
      Identity is the Firebase token; forging localStorage changes pixels,
      not permissions.

   3. Expose AECAuth for signin.html and admin.html.
   ========================================================================== */
(function () {
  'use strict';

  var DB_HOST = 'applied-economics-club-default-rtdb.firebaseio.com';

  firebase.initializeApp({
    apiKey: 'AIzaSyAU7CyoTpnV_6qplpS0Nlysg6JNvni8cBU',
    authDomain: 'applied-economics-club.firebaseapp.com',
    databaseURL: 'https://' + DB_HOST,
    projectId: 'applied-economics-club'
  });
  var auth = firebase.auth();

  function eKey(email) {
    return String(email || '').replace(/[.@#$[\]/]/g, '_');
  }

  // ── 1. Token-attaching fetch wrapper ────────────────────────────────────
  // Firebase restores the signed-in session ASYNCHRONOUSLY on every page
  // load. Pages fire their data requests immediately, so without waiting,
  // the first requests go out unauthenticated, the rules 401 them, and
  // every list renders empty. Database calls therefore wait for the first
  // auth-state resolution before leaving the building.
  var rawFetch = window.fetch.bind(window);
  var authReady = new Promise(function (resolve) {
    var un = auth.onAuthStateChanged(function () { un(); resolve(); });
  });
  window.fetch = function (input, init) {
    try {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      if (url.indexOf(DB_HOST) !== -1 && url.indexOf('.json') !== -1 &&
          url.indexOf('auth=') === -1) {
        return authReady.then(function () {
          var u = auth.currentUser;
          if (!u) return rawFetch(input, init);
          return u.getIdToken().then(function (t) {
            var sep = url.indexOf('?') === -1 ? '?' : '&';
            return rawFetch(url + sep + 'auth=' + encodeURIComponent(t), init);
          });
        });
      }
    } catch (e) { /* fall through to raw */ }
    return rawFetch(input, init);
  };

  // ── 2. Session cache sync ───────────────────────────────────────────────
  var readyCallbacks = [];
  var settled = false;

  auth.onAuthStateChanged(function (user) {
    if (user && user.email) {
      // Fetch the member record (token now attaches automatically).
      rawFetchMember(user).then(function (m) {
        var session = {
          email: user.email,
          name: (m && m.name) || user.displayName || user.email.split('@')[0],
          isAdmin: !!(m && m.isAdmin),
          uid: user.uid,
          loginAt: Date.now()
        };
        try { localStorage.setItem('aec-session', JSON.stringify(session)); } catch (e) {}
        applyBodyClasses(session);
        settle();
      });
    } else {
      try { localStorage.removeItem('aec-session'); } catch (e) {}
      var b = document.body || document.documentElement;
      b.classList.remove('is-authed', 'is-admin');
      settle();
    }
  });

  function rawFetchMember(user) {
    return user.getIdToken().then(function (t) {
      return rawFetch('https://' + DB_HOST + '/members/' + eKey(user.email) +
                      '.json?auth=' + encodeURIComponent(t));
    }).then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }

  function applyBodyClasses(s) {
    var b = document.body || document.documentElement;
    b.classList.add('is-authed');
    b.classList.toggle('is-admin', s.isAdmin === true);
  }

  function settle() {
    settled = true;
    while (readyCallbacks.length) readyCallbacks.shift()(auth.currentUser);
  }

  // ── 3. Public surface ───────────────────────────────────────────────────
  window.AECAuth = {
    eKey: eKey,
    user: function () { return auth.currentUser; },
    ready: function (cb) { settled ? cb(auth.currentUser) : readyCallbacks.push(cb); },
    token: function () {
      var u = auth.currentUser;
      return u ? u.getIdToken() : Promise.resolve(null);
    },
    signIn: function (email, password) {
      return auth.signInWithEmailAndPassword(email, password);
    },
    signUp: function (email, password) {
      return auth.createUserWithEmailAndPassword(email, password);
    },
    sendReset: function (email) {
      return auth.sendPasswordResetEmail(email);
    },
    signOut: function () {
      try { localStorage.removeItem('aec-session'); } catch (e) {}
      return auth.signOut();
    }
  };
})();
