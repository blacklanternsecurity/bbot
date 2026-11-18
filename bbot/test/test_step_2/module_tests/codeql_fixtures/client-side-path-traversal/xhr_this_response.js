// a parameter picks the help page, read back through `this` in the request's handler
var request = new XMLHttpRequest();
request.onload = function () {
  document.getElementById("help").innerHTML = this.responseText; // $ client-side-path-traversal
};
request.open("GET", "/help/" + new URLSearchParams(location.search).get("topic"));
request.send();
