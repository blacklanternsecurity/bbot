// an undecoded parameter is still a whole URL: ?next=https://evil.example needs nothing encoded
(function () {
  var next = location.search.split("next=")[1];
  if (next) {
    window.location.href = next; // $ open-redirect
  }
})();
