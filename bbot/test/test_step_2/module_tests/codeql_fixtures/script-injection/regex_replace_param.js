// replace() keeping only a parameter's value, which is then compiled
(function () {
  var source = document.location.search.replace(/.*\bfoo\s*=\s*([^;]*).*/, "$1");
  var fn = new Function(source); // $ script-injection
  fn();
})();
