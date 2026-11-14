// indexOf() accepts any origin that contains the trusted one, like https://trusted.example.com.evil.net
window.addEventListener("message", function (e) {
  if (e.origin.indexOf("trusted.example.com") > -1) {
    document.getElementById("notice").innerHTML = e.data; // $ dom-xss
  }
});
