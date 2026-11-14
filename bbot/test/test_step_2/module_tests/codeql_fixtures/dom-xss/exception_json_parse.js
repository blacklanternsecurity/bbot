// V8's JSON.parse errors quote the input
(function () {
  try {
    JSON.parse(decodeURIComponent(location.hash.substring(1)));
  } catch (e) {
    document.getElementById("error").innerHTML = "Error: " + e.message; // $ dom-xss
  }
})();
