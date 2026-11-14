// the last path segment, decoded and evaluated
(function () {
  var segment = location.pathname.split("/").pop();
  eval(decodeURI(segment)); // $ script-injection
})();
