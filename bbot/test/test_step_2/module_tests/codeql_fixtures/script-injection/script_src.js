// a script loaded from a URL taken from the query string
(function () {
  var script = document.createElement("script");
  script.src = new URLSearchParams(location.search).get("plugin"); // $ script-injection
  document.head.appendChild(script);
})();
