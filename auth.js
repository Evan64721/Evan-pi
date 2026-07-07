/* auth.js — client for the Evan-pi accounts + stats backend.
 *
 * All calls hit the API that nginx proxies to the Python service under /api/.
 * The session lives in an HttpOnly cookie the browser sends automatically, so
 * there are no tokens or passwords kept in JS/localStorage. Every method
 * returns a Promise.
 *
 *   EvAuth.me()                       -> { user: string|null, stats: [...]|null }
 *   EvAuth.signup(username, password) -> { user, stats }   (throws on error)
 *   EvAuth.login(username, password)  -> { user, stats }   (throws on error)
 *   EvAuth.logout()                   -> { user: null }
 *   EvAuth.recordResult(game, outcome)-> { stats } | undefined  (never throws)
 *
 * A stats entry is { key, label, wins, games, winRate } with winRate 0–100.
 */
(function (global) {
  "use strict";

  var BASE = "/api";

  function req(path, opts) {
    opts = opts || {};
    return fetch(BASE + path, {
      method: opts.method || "GET",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: opts.body
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          throw new Error(data.error || ("Request failed (" + res.status + ")"));
        }
        return data;
      });
    });
  }

  var Auth = {
    me: function () {
      return req("/me");
    },

    signup: function (username, password) {
      return req("/signup", {
        method: "POST",
        body: JSON.stringify({ username: username, password: password })
      });
    },

    login: function (username, password) {
      return req("/login", {
        method: "POST",
        body: JSON.stringify({ username: username, password: password })
      });
    },

    logout: function () {
      return req("/logout", { method: "POST" });
    },

    // Fire-and-forget: records a result for the signed-in player. Silently
    // does nothing if the request fails or nobody is signed in (server 401).
    recordResult: function (game, outcome) {
      return req("/record", {
        method: "POST",
        body: JSON.stringify({ game: game, outcome: outcome })
      }).catch(function () { /* ignore — stats are best-effort */ });
    }
  };

  global.EvAuth = Auth;
})(window);
