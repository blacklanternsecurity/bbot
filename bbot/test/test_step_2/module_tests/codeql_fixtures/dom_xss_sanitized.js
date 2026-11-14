// SAFE: user input is sanitized with DOMPurify before innerHTML
var userInput = decodeURIComponent(location.hash.substring(1));
var clean = DOMPurify.sanitize(userInput);
document.getElementById("output").innerHTML = clean;
