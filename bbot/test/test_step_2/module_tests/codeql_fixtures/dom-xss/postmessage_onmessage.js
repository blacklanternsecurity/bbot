// a handler assigned to window.onmessage
window.onmessage = function (event) {
  var msg = event.data;
  if (msg && msg.action === "render") {
    document.getElementById("widget").innerHTML = msg.html; // $ dom-xss
  }
};
