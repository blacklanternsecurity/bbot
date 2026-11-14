// checks that a value holds no "<" before it's written as HTML, and the branch that runs when it does
(function () {
  var q = new URLSearchParams(location.search).get("q");
  var el = document.getElementById("out");
  if (/[<>'"&]/.test(q)) {
    el.innerHTML = q; // $ dom-xss
  } else {
    el.innerHTML = q;
  }
  if (!q.includes("<")) {
    el.innerHTML = "<p>" + q + "</p>";
  }
  if (q.indexOf("<") === -1) {
    el.innerHTML = "<span>" + q + "</span>";
  }
  if (/[<>]/.exec(q) == null) {
    el.innerHTML = q;
  }
})();
