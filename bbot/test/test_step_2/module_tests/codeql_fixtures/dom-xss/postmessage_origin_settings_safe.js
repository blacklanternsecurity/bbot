// handlers that only accept messages from an origin the page keeps in its settings or a variable
var Settings = { trustedUrl: "https://trusted.example.com" };
var TRUSTED = "https://trusted.example.com";
window.addEventListener("message", function (e) {
  if (e.origin !== Settings.trustedUrl) return;
  document.getElementById("a").innerHTML = e.data;
});
window.addEventListener("message", function (e) {
  if (e.origin === TRUSTED) {
    document.getElementById("b").innerHTML = e.data;
  }
});
