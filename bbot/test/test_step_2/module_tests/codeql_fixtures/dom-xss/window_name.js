// window.name is set by whichever page opened or framed this one
(function () {
  document.getElementById("welcome").innerHTML = "Hello " + window.name; // $ dom-xss
})();
