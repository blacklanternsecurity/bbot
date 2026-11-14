// SAFE: setTimeout with function reference, not string
var action = new URLSearchParams(location.search).get("action");
setTimeout(function() { console.log(action); }, 1000);
