// replace() with a string only replaces the first "<"
(function () {
  var q = new URLSearchParams(location.search).get("q");
  document.getElementById("results").innerHTML = "Results for " + q.replace("<", "&lt;"); // $ dom-xss
})();
