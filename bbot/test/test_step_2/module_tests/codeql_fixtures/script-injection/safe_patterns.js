// evaluation that the attacker can't reach, and parsing that never runs code
(function () {
  var action = new URLSearchParams(location.search).get("action");
  setTimeout(function () {
    console.log(action);
  }, 1000);
  eval("1 + 1");
  var data = JSON.parse(decodeURIComponent(location.hash.slice(1)));
  console.log(data);
  // the whole URL, undecoded, starts "http:" and has no newline to end the comment that follows
  eval(location.href);
  var script = document.createElement("script");
  script.src = "/static/js/" + encodeURIComponent(action) + ".js";
  document.head.appendChild(script);
})();
