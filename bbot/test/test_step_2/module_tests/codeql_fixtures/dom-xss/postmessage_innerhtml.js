// any page can post a message to this one
window.addEventListener("message", function (e) {
  document.getElementById("ads").innerHTML = e.data; // $ dom-xss
});
