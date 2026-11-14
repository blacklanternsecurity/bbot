// a function named sanitize that doesn't sanitize
(function () {
  function sanitize(value) {
    return value.trim();
  }
  var name = new URLSearchParams(location.search).get("name");
  document.getElementById("name").innerHTML = sanitize(name); // $ dom-xss
})();
