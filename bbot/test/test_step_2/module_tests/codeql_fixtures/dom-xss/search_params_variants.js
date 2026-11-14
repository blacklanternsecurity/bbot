// every way of reading URLSearchParams decodes
(function () {
  var params = new URLSearchParams(location.search);
  document.getElementById("tags").innerHTML = params.getAll("tag").join(", "); // $ dom-xss

  var fromEntries = Object.fromEntries(new URLSearchParams(location.search));
  document.getElementById("title").innerHTML = fromEntries.title; // $ dom-xss

  var fromIterator = Object.fromEntries(new URLSearchParams(location.search).entries());
  document.getElementById("subtitle").innerHTML = fromIterator.subtitle; // $ dom-xss

  for (var [key, value] of new URLSearchParams(location.search)) {
    document.getElementById(key).innerHTML = value; // $ dom-xss
  }

  var output = "";
  new URLSearchParams(window.location.search).forEach(function (value, key) {
    output += key + ": " + value + "<br>";
  });
  document.getElementById("output").innerHTML = output; // $ dom-xss

  var url = new URL(window.location.href);
  document.getElementById("name").innerHTML = url.searchParams.get("name"); // $ dom-xss
})();
