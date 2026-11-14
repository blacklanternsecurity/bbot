// every way of setting the page's location
(function () {
  var params = new URLSearchParams(location.search);
  var next = params.get("next");
  if (params.has("a")) window.location = next; // $ open-redirect
  if (params.has("b")) location.href = next; // $ open-redirect
  if (params.has("c")) document.location = next; // $ open-redirect
  if (params.has("d")) window.location.replace(next); // $ open-redirect
  if (params.has("e")) location.assign(next); // $ open-redirect
  if (params.has("f")) top.location.href = next; // $ open-redirect
  if (params.has("g")) window.open(next); // $ open-redirect
  if (params.has("h")) {
    var loc = window.location;
    loc.href = next; // $ open-redirect
  }
})();
