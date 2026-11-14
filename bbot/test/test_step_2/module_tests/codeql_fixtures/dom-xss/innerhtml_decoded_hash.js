// the decoded fragment rendered with innerHTML
(function () {
  var userInput = decodeURIComponent(location.hash.substring(1));
  document.getElementById("output").innerHTML = userInput; // $ dom-xss
})();
