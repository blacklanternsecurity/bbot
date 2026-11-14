// VULNERABLE: location.hash flows through jQuery .html()
var hash = location.hash.substring(1);
$("#content").html(hash);
