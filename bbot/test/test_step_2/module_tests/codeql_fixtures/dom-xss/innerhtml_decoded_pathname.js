// the last path segment, decoded, rendered as a heading
(function () {
  var slug = decodeURIComponent(location.pathname.split("/").pop());
  document.querySelector("h1").innerHTML = slug.replace(/-/g, " "); // $ dom-xss
})();
