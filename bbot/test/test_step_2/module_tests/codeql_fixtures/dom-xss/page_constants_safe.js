// parameters and markup that come from the page's own code
(function () {
  var defaults = new URLSearchParams("view=grid&sort=name");
  document.getElementById("view").innerHTML = defaults.get("view");
  document.write("<h1>Hello World</h1>");
  var saved = localStorage.getItem("theme");
  document.getElementById("theme").innerHTML = "Theme: " + saved;
  var user = document.cookie.split("username=")[1];
  document.getElementById("profile").innerHTML = user;
})();
