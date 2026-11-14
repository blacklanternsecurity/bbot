// handlers that only accept messages from origins they name exactly
window.addEventListener("message", function (event) {
  if (event.origin !== "https://trusted.example.com") return;
  document.getElementById("a").innerHTML = event.data;
});
window.addEventListener("message", function (event) {
  if (event.origin === "https://one.example.com" || event.origin === "https://two.example.com") {
    document.getElementById("b").innerHTML = event.data.html;
  }
});
window.addEventListener("message", function (event) {
  var allowed = ["https://one.example.com", "https://two.example.com"];
  if (allowed.indexOf(event.origin) === -1) {
    return;
  }
  document.getElementById("c").innerHTML = event.data;
});
