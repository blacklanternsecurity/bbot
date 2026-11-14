// VULNERABLE: postMessage with wildcard origin leaks sensitive data
var secret = document.cookie;
parent.postMessage(secret, "*");
