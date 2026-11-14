// SAFE: location.hash flows to textContent (not a sink)
var userInput = decodeURIComponent(location.hash.substring(1));
document.getElementById("output").textContent = userInput;
