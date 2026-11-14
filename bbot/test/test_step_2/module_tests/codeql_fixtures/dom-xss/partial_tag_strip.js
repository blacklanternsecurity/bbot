// removing "<" only when a word follows still leaves "< " and "</"
(function () {
  var q = new URLSearchParams(location.search).get("q");
  document.getElementById("results").innerHTML = q.replace(/<\w+/g, ""); // $ dom-xss
})();
