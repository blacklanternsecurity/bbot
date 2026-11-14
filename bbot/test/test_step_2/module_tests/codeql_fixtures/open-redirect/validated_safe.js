// return URLs checked before use
(function () {
  var next = new URLSearchParams(location.search).get("next");
  var url = new URL(next, location.origin);
  if (url.origin === location.origin) {
    location.href = url.href;
  }
  var allowed = ["/home", "/account"];
  if (allowed.indexOf(next) !== -1) {
    location.href = next;
  }
})();
