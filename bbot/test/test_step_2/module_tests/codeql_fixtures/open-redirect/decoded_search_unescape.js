// a decoded query parameter as the page's location
(function () {
  var next = unescape(location.search.split("next=")[1]);
  window.location.href = next; // $ open-redirect
})();
