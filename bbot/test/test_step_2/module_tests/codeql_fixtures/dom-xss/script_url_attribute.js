// setAttribute with an attribute that takes a URL
(function () {
  var form = document.querySelector("form");
  form.setAttribute("action", decodeURIComponent(location.hash.substring(1))); // $ dom-xss
})();
