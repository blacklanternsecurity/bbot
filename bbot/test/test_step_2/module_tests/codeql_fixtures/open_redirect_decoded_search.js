// VULNERABLE: a decoded query parameter becomes the page's location
var next = unescape(location.search.split("next=")[1]);
window.location.href = next;
