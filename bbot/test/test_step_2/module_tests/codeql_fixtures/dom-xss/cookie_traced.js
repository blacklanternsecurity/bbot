// a parameter saved to a cookie, and later rendered from it
(function () {
  var q = new URLSearchParams(location.search).get("q");
  if (q) {
    document.cookie = "lastSearch=" + q + "; path=/";
  }
  var match = document.cookie.match(/lastSearch=([^;]*)/);
  if (match) {
    document.getElementById("last").innerHTML = "Last search: " + match[1]; // $ dom-xss
  }
})();
