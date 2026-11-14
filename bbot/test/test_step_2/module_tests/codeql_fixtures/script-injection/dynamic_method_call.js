// the attacker picks which global function runs, and its argument
(function () {
  var params = new URLSearchParams(location.search);
  var callback = params.get("callback");
  window[callback](params.get("arg")); // $ script-injection
})();
