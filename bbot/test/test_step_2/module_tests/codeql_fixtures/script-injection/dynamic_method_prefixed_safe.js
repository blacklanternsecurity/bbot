// a fixed prefix limits the attacker to the page's own handlers
(function () {
  var params = new URLSearchParams(location.search);
  window["handle" + params.get("event")](params.get("arg"));
})();
