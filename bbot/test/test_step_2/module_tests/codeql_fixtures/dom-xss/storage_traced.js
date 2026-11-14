// a parameter saved to localStorage, and later rendered from it
(function () {
  var params = new URLSearchParams(location.search);
  if (params.has("name")) {
    localStorage.setItem("displayName", params.get("name"));
  }
  var saved = localStorage.getItem("displayName");
  document.getElementById("greeting").innerHTML = "Welcome back, " + saved; // $ dom-xss
})();
