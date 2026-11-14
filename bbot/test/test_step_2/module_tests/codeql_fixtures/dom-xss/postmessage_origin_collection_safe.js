// handlers that only accept origins in a collection the page keeps
(function () {
  var allowedOrigins = window.ALLOWED_ORIGINS;
  var trusted = new Set(["https://one.example.com", "https://two.example.com"]);
  window.addEventListener("message", function (e) {
    if (allowedOrigins.includes(e.origin)) {
      document.getElementById("a").innerHTML = e.data;
    }
  });
  window.addEventListener("message", function (e) {
    if (!trusted.has(e.origin)) return;
    document.getElementById("b").innerHTML = e.data;
  });
})();
