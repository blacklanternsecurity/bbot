// "/\evil.example" passes both checks, and browsers read the backslash as a slash
(function () {
  var next = new URLSearchParams(location.search).get("next");
  if (next && next.startsWith("/") && !next.startsWith("//")) {
    location.href = next; // $ open-redirect
  }
})();
