// an inline script built from the fragment
(function () {
  var script = document.createElement("script");
  script.text = "var config = " + decodeURIComponent(location.hash.slice(1)) + ";"; // $ script-injection
  document.body.appendChild(script);
})();
