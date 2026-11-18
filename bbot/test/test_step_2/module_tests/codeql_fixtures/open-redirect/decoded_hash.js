// a decoded fragment as the page's location
(function () {
  var target = decodeURIComponent(location.hash.substring(1));
  window.location.href = target; // $ dom-xss
})();
