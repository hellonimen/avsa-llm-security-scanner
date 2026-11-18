// AVSA - live target reachability indicator ("is anything listening at
// this URL right now?"). Pure UI sugar: calls GET /ping?url=... and paints
// a dot/text next to a Target field's label. Debounced on input, and
// checked once automatically on page load for every field that already has
// a value (so the dot is live without the user needing to type anything).
// Never touches the scan form itself - a red dot does not disable Run;
// the target can come back online, or the user can fix the field, before
// they submit.

(function () {
  var timers = {};

  function paint(fieldId, state, text) {
    var el = document.getElementById("ping-status-" + fieldId);
    if (!el) return;
    el.classList.remove("checking", "online", "offline");
    el.classList.add(state);
    var t = el.querySelector(".ping-text");
    if (t) t.textContent = text;
  }

  function check(fieldId) {
    var input = document.getElementById(fieldId);
    if (!input) return;
    var url = input.value.trim();
    if (!url) {
      paint(fieldId, "offline", "no target");
      return;
    }
    paint(fieldId, "checking", "checking\u2026");
    fetch("/ping?url=" + encodeURIComponent(url))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (input.value.trim() !== url) return; // field changed since - stale
        paint(fieldId, data.reachable ? "online" : "offline", data.reachable ? "online" : "unreachable");
      })
      .catch(function () {
        if (input.value.trim() !== url) return;
        paint(fieldId, "offline", "check failed");
      });
  }

  window.avsaSchedulePing = function (fieldId) {
    clearTimeout(timers[fieldId]);
    timers[fieldId] = setTimeout(function () { check(fieldId); }, 500);
  };

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".ping-status").forEach(function (el) {
      var fieldId = el.id.replace("ping-status-", "");
      check(fieldId);
    });
  });
})();
