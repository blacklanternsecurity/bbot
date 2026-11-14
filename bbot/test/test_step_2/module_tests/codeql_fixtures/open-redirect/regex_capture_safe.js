// regular expressions that capture the protocol, or the whole URL, don't hand the attacker its start
(function () {
  var protocol = /^([a-z]+:)/.exec(window.location.href)[1];
  window.location.href = protocol + "//example.com/";
  var whole = /(.*)/.exec(window.location.href)[1];
  window.location.href = whole;
})();
