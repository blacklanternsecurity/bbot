// handlers that compare the origin with something the sender can choose, or with nothing at all
window.addEventListener("message", function (e) {
  var parent = new URLSearchParams(location.search).get("parent");
  if (e.origin !== parent) return;
  document.getElementById("a").innerHTML = e.data; // $ dom-xss
});
window.addEventListener("message", function (e) {
  if (e.origin !== e.data.origin) return;
  document.getElementById("b").innerHTML = e.data.html; // $ dom-xss
});
window.addEventListener("message", function (e) {
  if (e.origin === undefined) return;
  document.getElementById("c").innerHTML = e.data; // $ dom-xss
});
