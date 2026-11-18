// a link built from a parameter and clicked by the script
(function () {
  var a = document.createElement("a");
  a.href = new URLSearchParams(location.search).get("download"); // $ dom-xss
  a.click();
})();
