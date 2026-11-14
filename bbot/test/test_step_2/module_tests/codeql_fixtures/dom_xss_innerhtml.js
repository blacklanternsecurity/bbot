// VULNERABLE: location.hash flows to innerHTML
var userInput = decodeURIComponent(location.hash.substring(1));
document.getElementById("output").innerHTML = userInput;
