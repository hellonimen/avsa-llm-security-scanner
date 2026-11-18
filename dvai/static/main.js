// Tiny UX nicety: keep the latest message in view on load.
(function () {
  var box = document.getElementById("messages");
  if (box) {
    box.scrollTop = box.scrollHeight;
  }
})();
