// every way of setting the page's location
(function () {
  var params = new URLSearchParams(location.search);
  var next = params.get("next");
  if (params.has("a")) window.location = next; // $ dom-xss
  if (params.has("b")) location.href = next; // $ dom-xss
  if (params.has("c")) document.location = next; // $ dom-xss
  if (params.has("d")) window.location.replace(next); // $ dom-xss
  if (params.has("e")) location.assign(next); // $ dom-xss
  if (params.has("f")) top.location.href = next; // $ dom-xss
  if (params.has("g")) window.open(next); // $ dom-xss
  if (params.has("h")) {
    var loc = window.location;
    loc.href = next; // $ dom-xss
  }
})();
