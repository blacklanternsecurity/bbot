// setTimeout and setInterval evaluate a string argument
(function () {
  var action = new URLSearchParams(location.search).get("action");
  setTimeout("doAction('" + action + "')", 1000); // $ script-injection
  setInterval(location.hash.slice(1), 5000); // $ script-injection
})();
