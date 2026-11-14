// a link built from a parameter and added to the page
(function () {
  var link = document.createElement("a");
  link.textContent = "Continue";
  link.href = new URLSearchParams(location.search).get("next"); // $ dom-xss
  document.body.appendChild(link);
})();
