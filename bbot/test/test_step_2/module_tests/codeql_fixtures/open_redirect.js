// VULNERABLE: location.hash flows to location.href (open redirect)
var target = decodeURIComponent(location.hash.substring(1));
window.location.href = target;
