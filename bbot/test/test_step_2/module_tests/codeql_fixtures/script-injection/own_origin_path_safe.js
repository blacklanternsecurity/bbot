// A script loaded from beside the page: its own origin, then its path, which starts with "/", so the host stays the
// page's own
(function () {
  var script = document.createElement("script");
  script.src = location.origin + location.pathname + "widget.js";
  document.head.appendChild(script);
})();
