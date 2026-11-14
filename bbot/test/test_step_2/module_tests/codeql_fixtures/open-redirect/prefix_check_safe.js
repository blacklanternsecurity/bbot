// a prefix check whose fixed part already pins the host
(function () {
  var url = new URLSearchParams(location.search).get("url");
  var dir = window.APP_DIR || "app";
  if (url.startsWith("https://example.com/" + dir)) {
    location.href = url;
  }
})();
