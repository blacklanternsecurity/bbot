// a preview frame filled from a parameter
(function () {
  var frame = document.getElementById("preview");
  frame.srcdoc = new URLSearchParams(location.search).get("preview"); // $ dom-xss
})();
