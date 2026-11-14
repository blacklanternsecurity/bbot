// SAFE: location.hash flows through jQuery .text() (not a sink)
var hash = location.hash.substring(1);
$("#content").text(hash);
