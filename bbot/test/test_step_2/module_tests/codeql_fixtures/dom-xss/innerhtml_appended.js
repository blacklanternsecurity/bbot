// markup added to what an element already holds is parsed along with it
(function () {
  var message = decodeURIComponent(location.hash.slice(1));
  document.getElementById("log").innerHTML += "<li>" + message + "</li>"; // $ dom-xss
  document.getElementById("code").textContent += message;
})();
