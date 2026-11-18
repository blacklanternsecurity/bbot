// each URL parameter the page reads by name, and where it goes
(function () {
  var params = new URLSearchParams(location.search.substring(1));
  // into the page's location: tested
  location.href = params.get("next");
  // written as HTML: tested
  document.getElementById("greeting").innerHTML = params.get("name");
  // only ever text: not tested
  document.getElementById("title").textContent = params.get("title");
  // a number: not tested
  document.getElementById("page").innerHTML = parseInt(params.get("page"), 10);
})();

// URLSearchParams over something other than the page's URL: not its parameters
(function () {
  var body = new URLSearchParams(document.getElementById("form").value);
  document.getElementById("echo").innerHTML = body.get("comment");
})();

// AngularJS reads the query through $location.search()
angular.module("app", []).run(function ($location, $window) {
  var search = $location.search();
  if (search.returnUrl) {
    $window.location = search.returnUrl;
  }
});
