// the fragment needs no encoded characters to be code: #alert(1)
(function () {
  var code = location.hash.substring(1);
  eval(code); // $ script-injection
})();
