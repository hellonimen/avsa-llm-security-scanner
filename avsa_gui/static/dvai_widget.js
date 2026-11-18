// DVAI chat widget -- a floating launcher + panel on every AVSA GUI page,
// so you can chat with the target you're scanning without leaving AVSA.
//
// Deliberately simple: the panel is just a styled <iframe> pointed at
// DVAI's own real /guest?embed=1 (a first-time visitor is auto-logged-in as
// a throwaway guest; embed=1 hides DVAI's topbar/sidebar so its real chat
// fits a small panel -- see dvai/app.py and dvai/templates/base.html). No
// API calls, no CORS, no message-passing between AVSA and DVAI -- it's a
// plain cross-origin iframe navigation, so the browser's own same-site
// cookie handling (both are 127.0.0.1, just different ports) is all that's
// needed for the guest session to work. Loaded lazily -- DVAI is only hit
// once the bubble is actually clicked, not on every AVSA page load.
(function () {
  var script = document.currentScript;
  var dvaiUrl = (script.getAttribute("data-dvai-url") || "http://127.0.0.1:5000").replace(/\/+$/, "");

  var launcher = document.createElement("button");
  launcher.type = "button";
  launcher.className = "dvai-widget-launcher";
  launcher.setAttribute("aria-label", "Chat with DVAI");
  launcher.innerHTML =
    '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">' +
    '<path d="M4 5.5C4 4.67157 4.67157 4 5.5 4H18.5C19.3284 4 20 4.67157 20 5.5V14.5C20 15.3284 19.3284 16 18.5 16H9L5 19.5V16H5.5C4.67157 16 4 15.3284 4 14.5V5.5Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>' +
    '<circle cx="9" cy="10" r="1.1" fill="currentColor"/><circle cx="12" cy="10" r="1.1" fill="currentColor"/><circle cx="15" cy="10" r="1.1" fill="currentColor"/>' +
    "</svg>";

  var panel = document.createElement("div");
  panel.className = "dvai-widget-panel";
  panel.innerHTML =
    '<div class="dvai-widget-head">' +
    '<span class="dvai-widget-title">DVAI Assistant</span>' +
    '<div class="dvai-widget-actions">' +
    '<a class="dvai-widget-fullsite" href="' + dvaiUrl + '/" target="_blank" rel="noopener">Open full site &#8599;</a>' +
    '<button type="button" class="dvai-widget-close" aria-label="Close chat">&times;</button>' +
    "</div>" +
    "</div>" +
    '<iframe class="dvai-widget-frame" title="DVAI chat" src="about:blank"></iframe>';

  document.body.appendChild(launcher);
  document.body.appendChild(panel);

  var frame = panel.querySelector(".dvai-widget-frame");
  var closeBtn = panel.querySelector(".dvai-widget-close");
  var loaded = false;

  function openPanel() {
    panel.classList.add("open");
    launcher.classList.add("open");
    if (!loaded) {
      frame.src = dvaiUrl + "/guest?embed=1";
      loaded = true;
    }
  }
  function closePanel() {
    panel.classList.remove("open");
    launcher.classList.remove("open");
  }

  launcher.addEventListener("click", function () {
    if (panel.classList.contains("open")) {
      closePanel();
    } else {
      openPanel();
    }
  });
  closeBtn.addEventListener("click", closePanel);
})();
