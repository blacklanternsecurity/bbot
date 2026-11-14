// decoded, the whole URL can be code: "http:" is a label, and the rest of the line a comment until a newline
(function () {
  eval(decodeURIComponent(location.href)); // $ script-injection
})();
