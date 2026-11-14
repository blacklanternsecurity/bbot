// a parameter compiled with the Function constructor
(function () {
  var fn = new Function(new URLSearchParams(location.search).get("code")); // $ script-injection
  fn();
})();
